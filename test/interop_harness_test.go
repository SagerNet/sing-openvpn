package test

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"text/template"
	"time"

	openvpn "github.com/sagernet/sing-openvpn"
	E "github.com/sagernet/sing/common/exceptions"

	typesapi "github.com/docker/docker/api/types"
	containerapi "github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/docker/docker/errdefs"
	"github.com/docker/docker/pkg/jsonmessage"
	"github.com/docker/docker/pkg/stdcopy"
	"github.com/docker/go-connections/nat"
)

const (
	openVPNInteropEnvVar         = "OPENVPN_IT"
	openVPNInteropDefaultVersion = "2.6.14"
	openVPNInteropRoot           = "/interop"
)

var (
	openVPNInteropClientOnce sync.Once
	openVPNInteropClientErr  error
	openVPNInteropClient     *client.Client

	openVPNInteropImageDescriptors = map[string]*openVPNInteropImageDescriptor{
		"2.4.12": {
			version:        "2.4.12",
			baseImage:      "ubuntu:20.04",
			packageVersion: "2.4.12-0ubuntu0.20.04.2",
			image:          "sing-openvpn-interop:2.4.12",
		},
		"2.5.11": {
			version:        "2.5.11",
			baseImage:      "ubuntu:22.04",
			packageVersion: "2.5.11-0ubuntu0.22.04.4",
			image:          "sing-openvpn-interop:2.5.11",
		},
		"2.6.14": {
			version:        "2.6.14",
			baseImage:      "debian:bookworm-slim",
			packageVersion: "2.6.14-0+deb12u2",
			image:          "sing-openvpn-interop:2.6.14",
		},
	}
)

type openVPNInteropImageDescriptor struct {
	version        string
	baseImage      string
	packageVersion string
	image          string
	buildOnce      sync.Once
	buildErr       error
	versionErr     error
}

type interopEnvironment struct {
	version string
	image   string
	docker  *client.Client
}

type interopWorkspace struct {
	root        string
	fixturesDir string
	renderedDir string
	logsDir     string
}

type staticPeerTemplateData struct {
	Protocol        string
	LocalHost       string
	LocalPort       int
	RemoteHost      string
	RemotePort      int
	UseFloat        bool
	UseNobind       bool
	TunnelLocal     string
	TunnelRemote    string
	SecretPath      string
	KeyDirection    int
	Cipher          string
	Auth            string
	LogPath         string
	ExplicitNotify  bool
	PingExitSeconds int64
}

type tlsServerTemplateData struct {
	Protocol             string
	Port                 int
	CAPath               string
	CertPath             string
	KeyPath              string
	TLSAuthPath          string
	TLSCryptPath         string
	TLSCryptV2Path       string
	TLSCryptV2Option     string
	Cipher               string
	Auth                 string
	DataCiphersDirective string
	DataCiphers          string
	DisableNCP           bool
	TunMTU               uint32
	Fragment             uint32
	MSSFix               uint32
	Compression          string
	CompressionLZO       string
	RenegotiationSeconds int64
	RequireUserPass      bool
	AuthScriptPath       string
	CRResponseScriptPath string
	ManagementPort       int
	PushLines            []string
	LogPath              string
}

type tlsClientTemplateData struct {
	Protocol             string
	RemoteHost           string
	RemotePort           int
	CAPath               string
	CertPath             string
	KeyPath              string
	TLSAuthPath          string
	TLSCryptPath         string
	TLSCryptV2Path       string
	Cipher               string
	Auth                 string
	DataCiphersDirective string
	DataCiphers          string
	Fragment             uint32
	MSSFix               uint32
	Compression          string
	CompressionLZO       string
	RenegotiationSeconds int64
	AuthFilePath         string
	RouteNoPull          bool
	LogPath              string
	ExplicitNotify       bool
}

type dockerContainerOptions struct {
	Name         string
	Image        string
	Command      []string
	Binds        []string
	PortBindings nat.PortMap
	Privileged   bool
}

type interopContainer struct {
	client      *client.Client
	containerID string
	name        string
}

type interopPacketLengthRecorder struct {
	access       sync.Mutex
	enabled      bool
	readLengths  []int
	writeLengths []int
}

func (r *interopPacketLengthRecorder) Begin() {
	r.access.Lock()
	r.readLengths = nil
	r.writeLengths = nil
	r.enabled = true
	r.access.Unlock()
}

func (r *interopPacketLengthRecorder) End() ([]int, []int) {
	r.access.Lock()
	r.enabled = false
	readLengths := append([]int{}, r.readLengths...)
	writeLengths := append([]int{}, r.writeLengths...)
	r.access.Unlock()
	return readLengths, writeLengths
}

func (r *interopPacketLengthRecorder) recordRead(n int) {
	r.access.Lock()
	if r.enabled {
		r.readLengths = append(r.readLengths, n)
	}
	r.access.Unlock()
}

func (r *interopPacketLengthRecorder) recordWrite(n int) {
	r.access.Lock()
	if r.enabled {
		r.writeLengths = append(r.writeLengths, n)
	}
	r.access.Unlock()
}

type interopRecordedConn struct {
	net.Conn
	recorder *interopPacketLengthRecorder
}

func (c *interopRecordedConn) Read(buffer []byte) (int, error) {
	n, err := c.Conn.Read(buffer)
	if n > 0 {
		c.recorder.recordRead(n)
	}
	return n, err
}

func (c *interopRecordedConn) Write(buffer []byte) (int, error) {
	n, err := c.Conn.Write(buffer)
	if n > 0 {
		c.recorder.recordWrite(n)
	}
	return n, err
}

func requireInteropEnvironmentVersion(t *testing.T, version string) interopEnvironment {
	t.Helper()
	if os.Getenv(openVPNInteropEnvVar) == "" {
		t.Skipf("%s is not set", openVPNInteropEnvVar)
	}
	descriptor, found := openVPNInteropImageDescriptors[version]
	if !found {
		t.Fatalf("unsupported OpenVPN interop version: %s", version)
	}
	dockerClient := mustDockerClient(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	_, err := dockerClient.Ping(ctx)
	if err != nil {
		t.Fatalf("docker daemon is unavailable: %v", err)
	}
	ensureDockerImage(t, dockerClient, "alpine:3.20")
	tunCheck := runDockerContainerAndWait(t, dockerClient, dockerContainerOptions{
		Name:       "sing-openvpn-interop-tun-check-" + sanitizeDockerName(t.Name()),
		Image:      "alpine:3.20",
		Command:    []string{"sh", "-lc", "[ -e /dev/net/tun ] && echo ok || echo no"},
		Privileged: true,
	}, 15*time.Second)
	if tunCheck.ExitCode != 0 || strings.TrimSpace(tunCheck.Logs) != "ok" {
		t.Fatalf("privileged containers do not expose /dev/net/tun: %s", strings.TrimSpace(tunCheck.Logs))
	}
	descriptor.buildOnce.Do(func() {
		inspectContext, cancelInspect := context.WithTimeout(context.Background(), 10*time.Second)
		_, _, inspectErr := dockerClient.ImageInspectWithRaw(inspectContext, descriptor.image)
		cancelInspect()
		if inspectErr == nil {
			descriptor.versionErr = verifyInteropImageVersion(t, dockerClient, descriptor, "cached")
			if descriptor.versionErr == nil {
				return
			}
		}
		if inspectErr != nil && !errdefs.IsNotFound(inspectErr) {
			descriptor.buildErr = inspectErr
			return
		}
		descriptor.buildErr = buildInteropImage(dockerClient, descriptor.image, filepath.Join("testdata", "openvpn", "docker"), descriptor.baseImage, descriptor.packageVersion)
		if descriptor.buildErr == nil {
			descriptor.versionErr = verifyInteropImageVersion(t, dockerClient, descriptor, "rebuilt")
		}
	})
	if descriptor.buildErr != nil {
		t.Fatalf("build OpenVPN %s interop image: %v", descriptor.version, descriptor.buildErr)
	}
	if descriptor.versionErr != nil {
		t.Fatalf("verify interop image version: %v", descriptor.versionErr)
	}
	return interopEnvironment{
		version: descriptor.version,
		image:   descriptor.image,
		docker:  dockerClient,
	}
}

func verifyInteropImageVersion(
	t *testing.T,
	dockerClient *client.Client,
	descriptor *openVPNInteropImageDescriptor,
	attempt string,
) error {
	t.Helper()
	versionCheck := runDockerContainerAndWait(t, dockerClient, dockerContainerOptions{
		Name:  "sing-openvpn-interop-version-" + sanitizeDockerName(descriptor.version+"-"+attempt+"-"+t.Name()),
		Image: descriptor.image,
		Command: []string{
			"sh",
			"-lc",
			"dpkg-query -W -f='${Version}\\n' openvpn && openvpn --version",
		},
	}, 15*time.Second)
	packageVersion, remainingOutput, hasVersionOutput := strings.Cut(versionCheck.Logs, "\n")
	if !hasVersionOutput {
		return E.New("missing OpenVPN version output: ", strings.TrimSpace(versionCheck.Logs))
	}
	if packageVersion != descriptor.packageVersion {
		return E.New("unexpected OpenVPN package version: expected ", descriptor.packageVersion, ", got ", packageVersion)
	}
	openVPNVersionLine, _, _ := strings.Cut(remainingOutput, "\n")
	versionFields := strings.Fields(openVPNVersionLine)
	if len(versionFields) < 2 || versionFields[0] != "OpenVPN" || versionFields[1] != descriptor.version {
		return E.New("unexpected OpenVPN version: expected ", descriptor.version, ", got ", openVPNVersionLine)
	}
	return nil
}

func mustDockerClient(t *testing.T) *client.Client {
	t.Helper()
	openVPNInteropClientOnce.Do(func() {
		clientOptions := []client.Opt{client.WithAPIVersionNegotiation()}
		dockerHost := os.Getenv("DOCKER_HOST")
		switch {
		case dockerHost != "":
			clientOptions = append(clientOptions, client.WithHost(dockerHost))
		case fileExists("/Users/sekai/.orbstack/run/docker.sock"):
			clientOptions = append(clientOptions, client.WithHost("unix:///Users/sekai/.orbstack/run/docker.sock"))
		case fileExists("/var/run/docker.sock"):
			clientOptions = append(clientOptions, client.WithHost("unix:///var/run/docker.sock"))
		default:
			openVPNInteropClientErr = E.New("docker socket not found")
			return
		}
		openVPNInteropClient, openVPNInteropClientErr = client.NewClientWithOpts(clientOptions...)
	})
	if openVPNInteropClientErr != nil {
		t.Fatalf("create docker client: %v", openVPNInteropClientErr)
	}
	return openVPNInteropClient
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func ensureDockerImage(t *testing.T, dockerClient *client.Client, imageRef string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	_, _, err := dockerClient.ImageInspectWithRaw(ctx, imageRef)
	if err == nil {
		return
	}
	if !errdefs.IsNotFound(err) {
		t.Fatalf("inspect docker image %s: %v", imageRef, err)
	}
	reader, err := dockerClient.ImagePull(ctx, imageRef, typesapi.ImagePullOptions{})
	if err != nil {
		t.Fatalf("pull docker image %s: %v", imageRef, err)
	}
	defer reader.Close()
	_, _ = io.Copy(io.Discard, reader)
}

func buildInteropImage(dockerClient *client.Client, imageTag string, contextDir string, baseImage string, packageVersion string) error {
	buildContext, err := buildDockerContextTar(contextDir)
	if err != nil {
		return err
	}
	defer buildContext.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	response, err := dockerClient.ImageBuild(ctx, buildContext, typesapi.ImageBuildOptions{
		Tags: []string{imageTag},
		BuildArgs: map[string]*string{
			"BASE_IMAGE":              &baseImage,
			"OPENVPN_PACKAGE_VERSION": &packageVersion,
		},
		Remove: true,
	})
	if err != nil {
		return err
	}
	defer response.Body.Close()
	var output bytes.Buffer
	err = jsonmessage.DisplayJSONMessagesStream(response.Body, &output, 0, false, nil)
	if err != nil {
		return E.Cause(err, "docker build failed\n", output.String())
	}
	return nil
}

func buildDockerContextTar(contextDir string) (io.ReadCloser, error) {
	buffer := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buffer)
	err := filepath.WalkDir(contextDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(contextDir, path)
		if err != nil {
			return err
		}
		relativePath = filepath.ToSlash(relativePath)
		if relativePath == "." {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		header, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		header.Name = relativePath
		if entry.IsDir() {
			header.Name += "/"
		}
		writeErr := tarWriter.WriteHeader(header)
		if writeErr != nil {
			return writeErr
		}
		if entry.IsDir() {
			return nil
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		defer file.Close()
		_, err = io.Copy(tarWriter, file)
		return err
	})
	if err != nil {
		_ = tarWriter.Close()
		return nil, err
	}
	err = tarWriter.Close()
	if err != nil {
		return nil, err
	}
	return io.NopCloser(bytes.NewReader(buffer.Bytes())), nil
}

func newInteropWorkspace(t *testing.T) interopWorkspace {
	t.Helper()
	root := t.TempDir()
	fixturesDir := filepath.Join(root, "fixtures")
	renderedDir := filepath.Join(root, "rendered")
	logsDir := filepath.Join(root, "logs")
	for _, path := range []string{fixturesDir, renderedDir, logsDir} {
		err := os.MkdirAll(path, 0o755)
		if err != nil {
			t.Fatalf("create interop workspace: %v", err)
		}
	}
	copyFixtureDir(t, filepath.Join("testdata", "openvpn", "pki"), fixturesDir)
	copyFixtureDir(t, filepath.Join("testdata", "openvpn", "scripts"), filepath.Join(root, "scripts"))
	return interopWorkspace{
		root:        root,
		fixturesDir: fixturesDir,
		renderedDir: renderedDir,
		logsDir:     logsDir,
	}
}

func copyFixtureDir(t *testing.T, sourceDir string, targetDir string) {
	t.Helper()
	err := filepath.WalkDir(sourceDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relativePath, err := filepath.Rel(sourceDir, path)
		if err != nil {
			return err
		}
		targetPath := filepath.Join(targetDir, relativePath)
		if entry.IsDir() {
			return os.MkdirAll(targetPath, 0o755)
		}
		mkdirErr := os.MkdirAll(filepath.Dir(targetPath), 0o755)
		if mkdirErr != nil {
			return mkdirErr
		}
		sourceInfo, err := os.Stat(path)
		if err != nil {
			return err
		}
		sourceFile, err := os.Open(path)
		if err != nil {
			return err
		}
		defer sourceFile.Close()
		targetFile, err := os.OpenFile(targetPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, sourceInfo.Mode())
		if err != nil {
			return err
		}
		defer targetFile.Close()
		_, err = io.Copy(targetFile, sourceFile)
		return err
	})
	if err != nil {
		t.Fatalf("copy interop fixtures: %v", err)
	}
}

func renderInteropTemplate(t *testing.T, templateName string, outputPath string, data any) {
	t.Helper()
	templatePath := filepath.Join("testdata", "openvpn", "config", templateName)
	templateContent, err := os.ReadFile(templatePath)
	if err != nil {
		t.Fatalf("read template %s: %v", templateName, err)
	}
	parsedTemplate, err := template.New(templateName).Parse(string(templateContent))
	if err != nil {
		t.Fatalf("parse template %s: %v", templateName, err)
	}
	outputFile, err := os.OpenFile(outputPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o644)
	if err != nil {
		t.Fatalf("create rendered config %s: %v", outputPath, err)
	}
	defer outputFile.Close()
	err = parsedTemplate.Execute(outputFile, data)
	if err != nil {
		t.Fatalf("render template %s: %v", templateName, err)
	}
}

func startInteropContainer(t *testing.T, dockerClient *client.Client, options dockerContainerOptions) *interopContainer {
	t.Helper()
	prepareInteropLogFiles(t, options.Binds)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	containerConfiguration := &containerapi.Config{
		Image: options.Image,
		Cmd:   options.Command,
		Tty:   false,
	}
	if len(options.PortBindings) > 0 {
		containerConfiguration.ExposedPorts = nat.PortSet{}
		for port := range options.PortBindings {
			containerConfiguration.ExposedPorts[port] = struct{}{}
		}
	}
	hostConfiguration := &containerapi.HostConfig{
		Privileged:   options.Privileged,
		Binds:        options.Binds,
		ExtraHosts:   []string{"host.docker.internal:host-gateway"},
		PortBindings: options.PortBindings,
	}
	createdContainer, err := dockerClient.ContainerCreate(ctx, containerConfiguration, hostConfiguration, nil, nil, options.Name)
	if err != nil {
		t.Fatalf("create docker container %s: %v", options.Name, err)
	}
	err = dockerClient.ContainerStart(ctx, createdContainer.ID, containerapi.StartOptions{})
	if err != nil {
		_ = removeInteropContainer(context.Background(), dockerClient, createdContainer.ID)
		t.Fatalf("start docker container %s: %v", options.Name, err)
	}
	containerHandle := &interopContainer{
		client:      dockerClient,
		containerID: createdContainer.ID,
		name:        options.Name,
	}
	t.Cleanup(func() {
		_ = removeInteropContainer(context.Background(), dockerClient, createdContainer.ID)
	})
	return containerHandle
}

func prepareInteropLogFiles(t *testing.T, binds []string) {
	t.Helper()
	var workspaceRoot string
	for _, bind := range binds {
		source, target, found := strings.Cut(bind, ":")
		if !found {
			continue
		}
		target, _, _ = strings.Cut(target, ":")
		if target == openVPNInteropRoot {
			workspaceRoot = source
			break
		}
	}
	if workspaceRoot == "" {
		return
	}
	renderedRoot := filepath.Join(workspaceRoot, "rendered")
	err := filepath.WalkDir(renderedRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return nil
		}
		configuration, err := os.Open(path)
		if err != nil {
			return err
		}
		defer configuration.Close()
		scanner := bufio.NewScanner(configuration)
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 2 || (fields[0] != "log" && fields[0] != "log-append") {
				continue
			}
			dockerLogPath := filepath.ToSlash(fields[1])
			if !strings.HasPrefix(dockerLogPath, openVPNInteropRoot+"/") {
				continue
			}
			relativeLogPath := strings.TrimPrefix(dockerLogPath, openVPNInteropRoot+"/")
			localLogPath := filepath.Join(workspaceRoot, filepath.FromSlash(relativeLogPath))
			if !strings.HasPrefix(localLogPath, filepath.Clean(workspaceRoot)+string(os.PathSeparator)) {
				return E.New("OpenVPN log path escapes interop workspace: ", dockerLogPath)
			}
			logFile, err := os.OpenFile(localLogPath, os.O_CREATE|os.O_WRONLY, 0o644)
			if err != nil {
				return err
			}
			if err = logFile.Close(); err != nil {
				return err
			}
		}
		return scanner.Err()
	})
	if err != nil {
		t.Fatalf("prepare readable OpenVPN interop logs: %v", err)
	}
}

func runDockerContainerAndWait(t *testing.T, dockerClient *client.Client, options dockerContainerOptions, timeout time.Duration) dockerWaitResult {
	t.Helper()
	containerHandle := startInteropContainer(t, dockerClient, options)
	return containerHandle.Wait(t, timeout)
}

type dockerWaitResult struct {
	ExitCode int64
	Logs     string
}

func (c *interopContainer) Wait(t *testing.T, timeout time.Duration) dockerWaitResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	statusCh, errCh := c.client.ContainerWait(ctx, c.containerID, containerapi.WaitConditionNotRunning)
	select {
	case waitErr := <-errCh:
		if waitErr != nil {
			logs := c.logs(context.Background())
			t.Fatalf("wait docker container %s: %v\nlogs:\n%s", c.name, waitErr, logs)
		}
	case status := <-statusCh:
		logs := c.logs(context.Background())
		return dockerWaitResult{
			ExitCode: status.StatusCode,
			Logs:     logs,
		}
	case <-ctx.Done():
		logs := c.logs(context.Background())
		_ = removeInteropContainer(context.Background(), c.client, c.containerID)
		t.Fatalf("docker container %s timed out\nlogs:\n%s", c.name, logs)
	}
	return dockerWaitResult{}
}

func (c *interopContainer) ExecDetached(t *testing.T, command []string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	execResponse, err := c.client.ContainerExecCreate(ctx, c.containerID, typesapi.ExecConfig{
		Cmd: command,
	})
	if err != nil {
		t.Fatalf("create command in docker container %s: %v", c.name, err)
	}
	err = c.client.ContainerExecStart(ctx, execResponse.ID, typesapi.ExecStartCheck{Detach: true})
	if err != nil {
		t.Fatalf("start command in docker container %s: %v", c.name, err)
	}
}

func (c *interopContainer) logs(ctx context.Context) string {
	logReader, err := c.client.ContainerLogs(ctx, c.containerID, containerapi.LogsOptions{
		ShowStdout: true,
		ShowStderr: true,
	})
	if err != nil {
		return fmt.Sprintf("read logs: %v", err)
	}
	defer logReader.Close()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	_, err = stdcopy.StdCopy(&stdout, &stderr, logReader)
	if err != nil {
		return fmt.Sprintf("decode logs: %v", err)
	}
	if stderr.Len() == 0 {
		return stdout.String()
	}
	if stdout.Len() == 0 {
		return stderr.String()
	}
	return stdout.String() + "\nSTDERR:\n" + stderr.String()
}

func removeInteropContainer(ctx context.Context, dockerClient *client.Client, containerID string) error {
	err := dockerClient.ContainerRemove(ctx, containerID, containerapi.RemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
	if err != nil && !errdefs.IsNotFound(err) {
		return err
	}
	return nil
}

type interopPacketCapture struct {
	container         *interopContainer
	localLogPath      string
	localDecodedPath  string
	dockerLogPath     string
	dockerPacketPath  string
	dockerDecodedPath string
}

func startInteropPacketCapture(t *testing.T, containerHandle *interopContainer, workspace interopWorkspace, name string, filter string) *interopPacketCapture {
	t.Helper()
	capture := &interopPacketCapture{
		container:         containerHandle,
		localLogPath:      filepath.Join(workspace.logsDir, name+".capture.log"),
		localDecodedPath:  filepath.Join(workspace.logsDir, name+".decoded.log"),
		dockerLogPath:     filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+".capture.log")),
		dockerPacketPath:  filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+".pcap")),
		dockerDecodedPath: filepath.ToSlash(filepath.Join(openVPNInteropRoot, "logs", name+".decoded.log")),
	}
	command := "exec tcpdump -i any -s 0 -U -nn -c 1 -w " + capture.dockerPacketPath + " '" + filter + "' > " + capture.dockerLogPath + " 2>&1"
	containerHandle.ExecDetached(t, []string{"bash", "-lc", command})
	waitForLogLine(t, capture.localLogPath, "listening on any", 10*time.Second)
	return capture
}

func (c *interopPacketCapture) Decode(t *testing.T) string {
	t.Helper()
	waitForLogLine(t, c.localLogPath, "captured", 10*time.Second)
	temporaryDecodedPath := c.dockerDecodedPath + ".tmp"
	decodeCommand := "tcpdump -nn -r " + c.dockerPacketPath + " > " + temporaryDecodedPath + " 2>&1 && mv " + temporaryDecodedPath + " " + c.dockerDecodedPath
	c.container.ExecDetached(t, []string{"bash", "-lc", decodeCommand})
	waitForFile(t, c.localDecodedPath, 10*time.Second)
	decodedPackets, err := os.ReadFile(c.localDecodedPath)
	if err != nil {
		t.Fatalf("read decoded packet capture: %v", err)
	}
	return string(decodedPackets)
}

func waitForFile(t *testing.T, path string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		_, err := os.Stat(path)
		if err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", path)
}

func waitForLogLine(t *testing.T, logPath string, want string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		logContent, err := os.ReadFile(logPath)
		if err == nil && strings.Contains(string(logContent), want) {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	logContent, _ := os.ReadFile(logPath)
	t.Fatalf("timed out waiting for %q in %s\n%s", want, logPath, string(logContent))
}

func waitForAnyLogLine(t *testing.T, logPath string, want []string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	lowerWant := make([]string, 0, len(want))
	for _, candidate := range want {
		trimmedCandidate := strings.TrimSpace(candidate)
		if trimmedCandidate == "" {
			continue
		}
		lowerWant = append(lowerWant, strings.ToLower(trimmedCandidate))
	}
	if len(lowerWant) == 0 {
		t.Fatalf("waitForAnyLogLine requires at least one wanted substring")
	}
	for time.Now().Before(deadline) {
		logContent, err := os.ReadFile(logPath)
		if err == nil {
			lowerLogContent := strings.ToLower(string(logContent))
			for _, candidate := range lowerWant {
				if strings.Contains(lowerLogContent, candidate) {
					return
				}
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	logContent, _ := os.ReadFile(logPath)
	t.Fatalf("timed out waiting for any of %q in %s\n%s", want, logPath, string(logContent))
}

func reserveUDPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve udp port: %v", err)
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port
}

func reserveTCPPort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve tcp port: %v", err)
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func bindPortDialContextWithRecorder(localPort int, recorder *interopPacketLengthRecorder) func(ctx context.Context, network string, address string) (net.Conn, error) {
	return func(ctx context.Context, network string, address string) (net.Conn, error) {
		var conn net.Conn
		var err error
		switch {
		case strings.HasPrefix(network, "udp"):
			localIP := net.IPv4zero
			if strings.Contains(network, "6") {
				localIP = net.IPv6zero
			}
			dialer := net.Dialer{
				LocalAddr: &net.UDPAddr{IP: localIP, Port: localPort},
			}
			conn, err = dialer.DialContext(ctx, network, address)
		case strings.HasPrefix(network, "tcp"):
			localIP := net.IPv4zero
			if strings.Contains(network, "6") {
				localIP = net.IPv6zero
			}
			dialer := net.Dialer{
				LocalAddr: &net.TCPAddr{IP: localIP, Port: localPort},
			}
			conn, err = dialer.DialContext(ctx, network, address)
		default:
			return nil, E.New("unsupported network: ", network)
		}
		if err != nil || recorder == nil {
			return conn, err
		}
		return &interopRecordedConn{Conn: conn, recorder: recorder}, nil
	}
}

type pushedLocalAddress struct {
	Prefix netip.Prefix
	Peer   netip.Addr
}

func formatPushedIfconfigIPv6(value pushedLocalAddress) string {
	prefix := value.Prefix
	if !prefix.IsValid() || !prefix.Addr().Is6() {
		return ""
	}
	if value.Peer.Is6() {
		return prefix.String() + " " + value.Peer.String()
	}
	return ""
}

func formatIfconfigPrefix(prefix netip.Prefix, topology string) string {
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return ""
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	return prefix.Addr().String() + " " + net.IP(mask).String()
}

func formatIPv4RoutePrefix(prefix netip.Prefix) string {
	prefix = prefix.Masked()
	if !prefix.IsValid() || !prefix.Addr().Is4() {
		return ""
	}
	mask := net.CIDRMask(prefix.Bits(), 32)
	return prefix.Addr().String() + " " + net.IP(mask).String()
}

func udpPortBinding(port int) nat.PortMap {
	containerPort := nat.Port(fmt.Sprintf("%d/udp", port))
	return nat.PortMap{
		containerPort: []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: fmt.Sprintf("%d", port)},
		},
	}
}

func udp6PortBinding(port int) nat.PortMap {
	containerPort := nat.Port(fmt.Sprintf("%d/udp", port))
	return nat.PortMap{
		containerPort: []nat.PortBinding{
			{HostIP: "::1", HostPort: fmt.Sprintf("%d", port)},
		},
	}
}

func tcpPortBinding(port int) nat.PortMap {
	containerPort := nat.Port(fmt.Sprintf("%d/tcp", port))
	return nat.PortMap{
		containerPort: []nat.PortBinding{
			{HostIP: "127.0.0.1", HostPort: fmt.Sprintf("%d", port)},
		},
	}
}

func tcp6PortBinding(port int) nat.PortMap {
	containerPort := nat.Port(fmt.Sprintf("%d/tcp", port))
	return nat.PortMap{
		containerPort: []nat.PortBinding{
			{HostIP: "::1", HostPort: fmt.Sprintf("%d", port)},
		},
	}
}

func sanitizeDockerName(name string) string {
	replacer := strings.NewReplacer("/", "-", "_", "-", " ", "-")
	return strings.ToLower(replacer.Replace(name))
}

func buildStaticICMPEchoRequest(t *testing.T, source netip.Addr, destination netip.Addr, identifier uint16, sequence uint16, payload []byte) []byte {
	t.Helper()
	if !source.Is4() || !destination.Is4() {
		t.Fatal("only IPv4 ICMP echo is implemented in the real interop harness")
	}
	icmpPacket := make([]byte, 8+len(payload))
	icmpPacket[0] = 8
	icmpPacket[1] = 0
	binary.BigEndian.PutUint16(icmpPacket[4:6], identifier)
	binary.BigEndian.PutUint16(icmpPacket[6:8], sequence)
	copy(icmpPacket[8:], payload)
	binary.BigEndian.PutUint16(icmpPacket[2:4], internetChecksum(icmpPacket))

	ipv4Packet := make([]byte, 20+len(icmpPacket))
	ipv4Packet[0] = 0x45
	ipv4Packet[1] = 0
	binary.BigEndian.PutUint16(ipv4Packet[2:4], uint16(len(ipv4Packet)))
	binary.BigEndian.PutUint16(ipv4Packet[4:6], 0)
	binary.BigEndian.PutUint16(ipv4Packet[6:8], 0)
	ipv4Packet[8] = 64
	ipv4Packet[9] = 1
	copy(ipv4Packet[12:16], source.AsSlice())
	copy(ipv4Packet[16:20], destination.AsSlice())
	binary.BigEndian.PutUint16(ipv4Packet[10:12], internetChecksum(ipv4Packet[:20]))
	copy(ipv4Packet[20:], icmpPacket)
	return ipv4Packet
}

func buildIPv4TCPSYNPacket(t *testing.T, source netip.Addr, destination netip.Addr, sourcePort uint16, destinationPort uint16, segmentSize uint16) []byte {
	t.Helper()
	if !source.Is4() || !destination.Is4() {
		t.Fatal("only IPv4 TCP is implemented in the real interop harness")
	}
	const (
		ipv4HeaderLength = 20
		tcpHeaderLength  = 24
	)
	packet := make([]byte, ipv4HeaderLength+tcpHeaderLength)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	binary.BigEndian.PutUint16(packet[4:6], 0x2345)
	packet[6] = 0x40
	packet[8] = 64
	packet[9] = 6
	sourceBytes := source.As4()
	destinationBytes := destination.As4()
	copy(packet[12:16], sourceBytes[:])
	copy(packet[16:20], destinationBytes[:])
	binary.BigEndian.PutUint16(packet[10:12], internetChecksum(packet[:ipv4HeaderLength]))
	tcpSegment := packet[ipv4HeaderLength:]
	binary.BigEndian.PutUint16(tcpSegment[0:2], sourcePort)
	binary.BigEndian.PutUint16(tcpSegment[2:4], destinationPort)
	binary.BigEndian.PutUint32(tcpSegment[4:8], 1)
	tcpSegment[12] = 6 << 4
	tcpSegment[13] = 0x02
	binary.BigEndian.PutUint16(tcpSegment[14:16], 65535)
	tcpSegment[20] = 2
	tcpSegment[21] = 4
	binary.BigEndian.PutUint16(tcpSegment[22:24], segmentSize)
	pseudoHeader := make([]byte, 12+len(tcpSegment))
	copy(pseudoHeader[0:4], sourceBytes[:])
	copy(pseudoHeader[4:8], destinationBytes[:])
	pseudoHeader[9] = 6
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(tcpSegment)))
	copy(pseudoHeader[12:], tcpSegment)
	binary.BigEndian.PutUint16(tcpSegment[16:18], internetChecksum(pseudoHeader))
	return packet
}

func buildStaticICMPEchoReply(request []byte) ([]byte, error) {
	if len(request) < 28 {
		return nil, E.New("short ipv4 icmp packet")
	}
	headerLength := int(request[0]&0x0f) * 4
	if len(request) < headerLength+8 || headerLength < 20 {
		return nil, E.New("invalid ipv4 header length")
	}
	if request[0]>>4 != 4 || request[9] != 1 {
		return nil, E.New("not an ipv4 icmp packet")
	}
	if request[headerLength] != 8 || request[headerLength+1] != 0 {
		return nil, E.New("not an icmp echo request")
	}
	reply := bytes.Clone(request)
	copy(reply[12:16], request[16:20])
	copy(reply[16:20], request[12:16])
	reply[8] = 64
	reply[10] = 0
	reply[11] = 0
	binary.BigEndian.PutUint16(reply[10:12], internetChecksum(reply[:headerLength]))
	reply[headerLength] = 0
	reply[headerLength+1] = 0
	reply[headerLength+2] = 0
	reply[headerLength+3] = 0
	binary.BigEndian.PutUint16(reply[headerLength+2:headerLength+4], internetChecksum(reply[headerLength:]))
	return reply, nil
}

func assertStaticICMPEchoReply(t *testing.T, request []byte, reply []byte) {
	t.Helper()
	err := validateStaticICMPEchoReply(request, reply)
	if err != nil {
		t.Fatalf("%s\nrequest=%x\nreply=%x", err, request, reply)
	}
}

func validateStaticICMPEchoReply(request []byte, reply []byte) error {
	if len(request) < 28 || len(reply) < 28 {
		return E.New("unexpected short icmp packets")
	}
	requestHeaderLength := int(request[0]&0x0f) * 4
	replyHeaderLength := int(reply[0]&0x0f) * 4
	if requestHeaderLength < 20 || replyHeaderLength < 20 || len(request) < requestHeaderLength+8 || len(reply) < replyHeaderLength+8 {
		return E.New("invalid ipv4 header lengths")
	}
	if reply[0]>>4 != 4 || reply[9] != 1 {
		return E.New("reply is not ipv4 icmp")
	}
	if !bytes.Equal(reply[12:16], request[16:20]) || !bytes.Equal(reply[16:20], request[12:16]) {
		return E.New("reply addresses do not match request")
	}
	if reply[replyHeaderLength] != 0 || reply[replyHeaderLength+1] != 0 {
		return E.New("reply is not an icmp echo reply")
	}
	if !bytes.Equal(reply[replyHeaderLength+4:], request[requestHeaderLength+4:]) {
		return E.New("reply icmp identifier/sequence/payload mismatch")
	}
	if internetChecksum(reply[:replyHeaderLength]) != 0 {
		return E.New("invalid ipv4 header checksum")
	}
	if internetChecksum(reply[replyHeaderLength:]) != 0 {
		return E.New("invalid icmp checksum")
	}
	return nil
}

func internetChecksum(packet []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(packet); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(packet[index : index+2]))
	}
	if len(packet)%2 == 1 {
		sum += uint32(packet[len(packet)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func buildInteropEchoPayload(payloadSize int) []byte {
	basePayload := []byte("sing-openvpn-tls")
	if payloadSize <= len(basePayload) {
		return append([]byte{}, basePayload...)
	}
	repeatCount := (payloadSize + len(basePayload) - 1) / len(basePayload)
	return bytes.Repeat(basePayload, repeatCount)[:payloadSize]
}

func waitForLogOccurrences(t *testing.T, logPath string, value string, expectedCount int, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		content, err := os.ReadFile(logPath)
		if err == nil && strings.Count(string(content), value) >= expectedCount {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %d occurrences of %q in %s", expectedCount, value, logPath)
}

func dumpInteropLogs(t *testing.T, workspace interopWorkspace) {
	t.Helper()
	if !t.Failed() {
		return
	}
	_ = filepath.WalkDir(workspace.logsDir, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() {
			return nil
		}
		if filepath.Ext(path) == ".pcap" {
			return nil
		}
		content, err := os.ReadFile(path)
		if err == nil {
			t.Logf("log %s:\n%s", path, string(content))
		}
		return nil
	})
}

func pushLinesForScenario(configuration openvpn.TunnelConfiguration) []string {
	var lines []string
	if configuration.Topology != "" {
		lines = append(lines, "topology "+configuration.Topology)
	}
	if configuration.TunMTU > 0 {
		lines = append(lines, fmt.Sprintf("tun-mtu %d", configuration.TunMTU))
	}
	for _, ifconfig := range configuration.LocalIPv4 {
		lines = append(lines, "ifconfig "+formatIfconfigPrefix(ifconfig, configuration.Topology))
	}
	for _, ifconfigIPv6 := range configuration.LocalIPv6 {
		ifconfigIPv6Value := formatPushedIfconfigIPv6(pushedLocalAddress{
			Prefix: ifconfigIPv6,
			Peer:   ifconfigIPv6.Masked().Addr().Next(),
		})
		if ifconfigIPv6Value != "" {
			lines = append(lines, "ifconfig-ipv6 "+ifconfigIPv6Value)
		}
	}
	if configuration.RouteGateway.IsValid() {
		lines = append(lines, "route-gateway "+configuration.RouteGateway.String())
	}
	for _, route := range configuration.IPv4Routes {
		lines = append(lines, "route "+formatIPv4RoutePrefix(route.Prefix))
	}
	for _, routeIPv6 := range configuration.IPv6Routes {
		lines = append(lines, "route-ipv6 "+routeIPv6.Prefix.String())
	}
	for _, dnsAddress := range configuration.DNS {
		if dnsAddress.Is4() {
			lines = append(lines, "dhcp-option DNS "+dnsAddress.String())
		} else if dnsAddress.Is6() {
			lines = append(lines, "dhcp-option DNS6 "+dnsAddress.String())
		}
	}
	for _, dhcpOption := range configuration.DHCPOptions {
		lines = append(lines, "dhcp-option "+dhcpOption)
	}
	if configuration.BlockIPv6 {
		lines = append(lines, "block-ipv6")
	}
	if configuration.BlockOutsideDNS {
		lines = append(lines, "block-outside-dns")
	}
	if configuration.RedirectGateway {
		lines = append(lines, "redirect-gateway")
	}
	return lines
}

func waitForClientIfconfig(t *testing.T, openVPNClient *openvpn.Client, timeout time.Duration) openvpn.TunnelConfiguration {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		configuration := openVPNClient.TunnelConfiguration()
		if len(configuration.LocalIPv4) > 0 {
			return configuration
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for client pushed ifconfig")
	return openvpn.TunnelConfiguration{}
}

func assertLogContains(t *testing.T, logPath string, values []string) {
	t.Helper()
	if len(values) == 0 {
		return
	}
	logContent, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log %s: %v", logPath, err)
	}
	for _, value := range values {
		if !strings.Contains(string(logContent), value) {
			t.Fatalf("expected %q in %s\n%s", value, logPath, string(logContent))
		}
	}
}
