package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

const APP_NAME = "minipot"

const DOCKER_FILE_BASE = `
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh
`

const PCAP_DOCKER_FILE = `
FROM alpine
COPY entrypoint.sh /entrypoint.sh
RUN apk update && apk add tcpdump && chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh
`
const PCAP_ENTRYPOINT = `
#!/bin/sh
tcpdump -i any -s 65535 -w /session.pcap
`
const ENTRYPOINT = `
#!/bin/bash
if [[ \"$USR\" != \"root\" ]]
then
	useradd -m -p thisisfake $USR -s /
	bin/bash
	su - $USR
else
	bash
fi
`
const DOCKER_CLIENT_ENV_NAME = "minipot-client-env:latest"

const ERR_FILE_OPEN = 1
const ERR_PRIVATE_KEY_LOAD = 2
const ERR_PRIVATE_KEY_PARSE = 3
const ERR_SSH_SERVE = 4
const ERR_SSH_ACCEPT = 5
const ERR_CONTAINER_ATTACH = 6
const ERR_CONTAINER_CREATE = 7
const ERR_CONTAINER_START = 8
const ERR_CONTAINER_NETWORK_CONNECT = 9
const ERR_DOCKER_INVALID_NETWORK_MODE = 10
const ERR_DOCKER_IMAGE_BUILD = 11
const ERR_DOCKER_ENGINE_CLIENT_CREATE = 12
const ERR_TAR_WRITE_HEADER = 13
const ERR_TAR_WRITE_BODY = 14

type Input struct {
	Data string
	Time time.Time
}

type authAttempt struct {
	Username   string
	Password   string
	Time       time.Time
	Successful bool
}

type sessionData struct {
	Id                   int
	GlobalId             string
	User                 string
	Password             string
	GuestEnvHostname     string
	SourceIp             string
	ClientVersion        string
	TimeStart            time.Time
	TimeEnd              time.Time
	AuthAttempts         []authAttempt
	UserInput            []Input
	ModifiedFiles        []string
	NetworkMode          string
	Image                string
	sessionTimeout       int
	inputTimeout         int
	TimedOutBySession    bool
	TimedOutByNoInput    bool
	environmentVariables []string
	PcapEnabled          bool
}

func main() {
	baseimage := flag.String("baseimage", "ubuntu:18.04", "Image to use as base for user environment build. Entrypoint will be overwritten.")
	debug := flag.Bool("debug", false, "Enable debug output.")
	outputDir := flag.String("outputdir", "./", "Directory to output session log files to.")
	globalSessionId := flag.String("id", "", "Global session id, for log file names etc. Defaults to epoch.")
	hostname := flag.String("hostname", "", "Hostname to use in container. Default is container default.")
	networkmode := flag.String("networkmode", "none", "Docker network mode to use for containers. Valid options are 'none', 'bridge' or 'host'. Defaults to 'none'. Use with caution!")
	sessionTimeout := flag.Int("sessiontimeout", 1800, "Timeout in seconds before closing a session. Default to 1800.")
	inputTimeout := flag.Int("inputtimeout", 300, "Timeout in seconds before closing a session when no input is detected. Default to 300.")
	pcapEnabled := flag.Bool("pcap", false, "Enable packet capture. Could potentially use up a lot of disk space.")
	privateKeyFile := flag.String("privatekey", "", "Path to private key for SSH server if providing your own is preferable. If left empty, one will be created for each session.")

	flag.Parse()

	logger := log.New(os.Stderr, fmt.Sprintf("%s: ", APP_NAME), log.Ldate|log.Ltime|log.Lshortfile)
	if *globalSessionId == "" {
		tstr := strconv.Itoa(int(time.Now().Unix()))
		globalSessionId = &tstr
	}

	usePcap := *pcapEnabled

	if *networkmode != "none" &&
		*networkmode != "bridge" &&
		*networkmode != "host" {
		logger.Println("No valid network mode given.")
		os.Exit(ERR_DOCKER_INVALID_NETWORK_MODE)
	}

	if *networkmode == "none" || *networkmode == "host" {
		usePcap = false
		logger.Println("WARNING: Disabling packet capture, only available in 'bridge' network mode.")
	}

	logger.Println("Starting minipot")
	logger.Println("Connecting to Docker engine")
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		logger.Println("Error whle creating Docker engine client: ", err)
		os.Exit(ERR_DOCKER_ENGINE_CLIENT_CREATE)
	}

	// Create tarball with Dockerfile and entrypoint for PCAP image
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)

	buildOutput := false
	if *debug {
		buildOutput = true
	}

	if usePcap {

		logger.Println("Starting PCAP image build")

		err = writeTar(tarWriter, "Dockerfile", []byte(PCAP_DOCKER_FILE))
		if err != nil {
			logger.Println("Error writing TAR: ", err)
		}
		err = writeTar(tarWriter, "entrypoint.sh", []byte(PCAP_ENTRYPOINT))
		if err != nil {
			logger.Println("Error writing TAR: ", err)
		}

		dockerContext := bytes.NewReader(buf.Bytes())

		// Build PCAP image
		imageBuildResponse, err := cli.ImageBuild(
			ctx,
			dockerContext,
			types.ImageBuildOptions{
				SuppressOutput: buildOutput,
				Context:        dockerContext,
				Dockerfile:     "Dockerfile",
				Remove:         true,
				Tags:           []string{"minipot-pcap:latest"}})
		if err != nil {
			log.Println("Error building image: ", err)
			os.Exit(ERR_DOCKER_IMAGE_BUILD)
		}
		defer imageBuildResponse.Body.Close()
		if *debug {
			_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
			if err != nil {
				log.Println("Error reading image build response: ", err)
				os.Exit(ERR_DOCKER_IMAGE_BUILD)
			}
		}
	}

	buf = new(bytes.Buffer)
	tarWriter = tar.NewWriter(buf)

	logger.Println("Starting image build from ", *baseimage)

	err = writeTar(tarWriter, "Dockerfile", []byte("FROM "+*baseimage+"\n"+DOCKER_FILE_BASE))
	if err != nil {
		logger.Println("Error writing TAR: ", err)
	}
	err = writeTar(tarWriter, "entrypoint.sh", []byte(ENTRYPOINT))
	if err != nil {
		logger.Println("Error writing TAR: ", err)
	}

	dockerContext := bytes.NewReader(buf.Bytes())

	// Build image
	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		dockerContext,
		types.ImageBuildOptions{
			SuppressOutput: buildOutput,
			Context:        dockerContext,
			Dockerfile:     "Dockerfile",
			Remove:         true,
			Tags:           []string{DOCKER_CLIENT_ENV_NAME}})
	if err != nil {
		log.Println("Error building image: ", err)
		os.Exit(ERR_DOCKER_IMAGE_BUILD)
	}
	defer imageBuildResponse.Body.Close()
	if *debug {
		_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
		if err != nil {
			log.Println("Error reading image build response: ", err)
			os.Exit(ERR_DOCKER_IMAGE_BUILD)
		}
	}

	logger.Println("Build complete")

	var privateKey []byte
	if *privateKeyFile != "" { // It needs some kind, either we supply one via file, or we create a new one for each session
		privateKey, err = ioutil.ReadFile(*privateKeyFile)
		if err != nil {
			logger.Println("Failed to load private key: ", err)
			os.Exit(ERR_PRIVATE_KEY_LOAD)
		}
	} else {
		privateKeyGen, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			logger.Println("Cannot generate RSA key: ", err)
			os.Exit(ERR_PRIVATE_KEY_LOAD)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKeyGen),
		})
	}

	private, err := ssh.ParsePrivateKey(privateKey)
	if err != nil {
		logger.Println("Failed to parse private key: ", err)
		os.Exit(ERR_PRIVATE_KEY_PARSE)
	}

	logger.Println("Serving SSH")
	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		logger.Println("SSH listen failed: ", err)
		os.Exit(ERR_SSH_SERVE)
	}

	sid := 0
	for {

		nConn, err := listener.Accept()
		if err != nil {
			logger.Println("SSH accept failed: ", err)
			os.Exit(ERR_SSH_ACCEPT)
		}

		session := sessionData{
			GlobalId:         *globalSessionId,
			Id:               sid,
			TimeStart:        time.Now(),
			GuestEnvHostname: *hostname,
			NetworkMode:      *networkmode,
			Image:            *baseimage,
			sessionTimeout:   *sessionTimeout,
			inputTimeout:     *inputTimeout,
			PcapEnabled:      usePcap,
			// environmentVariables: environmentVariables,
		}

		config := &ssh.ServerConfig{
			PasswordCallback: authCallBackWrapper(&session, *debug, *logger),
		}

		config.AddHostKey(private)
		logger.Printf("New SSH session (%d)\n", session.Id)
		go handleClient(nConn, cli, config, &session, *outputDir, *debug)
		sid++
	}
}

func handleClient(nConn net.Conn, cli *client.Client, config *ssh.ServerConfig, session *sessionData, outputDir string, debug bool) {

	logger := log.New(os.Stderr, fmt.Sprintf("%s (session %d): ", APP_NAME, session.Id), log.Ldate|log.Ltime|log.Lshortfile)

	ctx := context.Background()
	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	if session.sessionTimeout > 0 {
		if debug {
			logger.Println("Session timeout is set to ", session.sessionTimeout, "seconds.")
		}
		go func() {
			time.Sleep(time.Duration(session.sessionTimeout) * time.Second) // Container timeout
			session.TimedOutBySession = true
			cancel()
		}()
	}

	if debug {
		logger.Println("Creating container.")
	}

	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Println("User failed to login: ", err)
		cancel()
	}

	networkName := fmt.Sprintf("%s-%d", session.GlobalId, session.Id)
	_, err = cli.NetworkCreate(ctx, networkName, types.NetworkCreate{
		Attachable: true,
	})
	if err != nil {
		logger.Println("Error while creating network. Might exist already, trying anyway.")
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        DOCKER_CLIENT_ENV_NAME,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		AttachStdout: true,
		OpenStdin:    true,
		Hostname:     session.GuestEnvHostname,
		Env:          append(session.environmentVariables, "USR="+session.User),
	},
		&container.HostConfig{
			AutoRemove:  true,
			NetworkMode: container.NetworkMode(session.NetworkMode),
		}, nil, nil, "")
	if err != nil {
		logger.Println("Error while creating container: ", err)
		os.Exit(ERR_CONTAINER_CREATE)
	}

	err = cli.NetworkConnect(ctx, networkName, resp.ID, &network.EndpointSettings{})
	if err != nil {
		logger.Println("Error connecting guest container to network: ", err)
		os.Exit(ERR_CONTAINER_NETWORK_CONNECT)
	}

	err = cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
	if err != nil {
		logger.Println("Error while starting container: ", err)
		os.Exit(ERR_CONTAINER_START)
	}
	var pcap = container.ContainerCreateCreatedBody{}
	if session.PcapEnabled {
		inspection, err := cli.ContainerInspect(ctx, resp.ID)
		if err != nil {
			logger.Println("Could not get container inspect:", err)
		}

		name := inspection.Name

		pcap, err = cli.ContainerCreate(ctx, &container.Config{
			Image: "minipot-pcap:latest",
		},
			&container.HostConfig{
				AutoRemove:  true,
				NetworkMode: container.NetworkMode("container:" + name),
			}, &network.NetworkingConfig{
				EndpointsConfig: map[string]*network.EndpointSettings{},
			}, nil, "")
		if err != nil {
			logger.Println("Error while creating container: ", err)
			os.Exit(ERR_CONTAINER_CREATE)
		}

		err = cli.ContainerStart(ctx, pcap.ID, types.ContainerStartOptions{})
		if err != nil {
			logger.Println("Error while starting container: ", err)
			os.Exit(ERR_CONTAINER_START)
		}
	}

	inputChan := make(chan byte)

	// Input collector
	go func() {
		line := ""
		for {
			b := <-inputChan
			if b == 127 { // DELETE
				line = fmt.Sprintf("%s<BACKSPACE>", line)
			} else if b == 9 {
				line = fmt.Sprintf("%s<TAB>", line)
			} else if b == 13 { // CR
				i := Input{
					Data: line,
					Time: time.Now(),
				}
				session.UserInput = append(session.UserInput, i)
				line = ""
			} else {
				line = fmt.Sprintf("%s%s", line, string(b))
			}
		}
	}()

	go func() {

		timeoutchan := make(chan bool)
		if session.inputTimeout > 0 {
			go func() {
				for {
					select {
					case <-timeoutchan:
					case <-time.After(time.Duration(session.inputTimeout) * time.Second): // Make this configurable
						session.TimedOutByNoInput = true
						cancel()
					}
				}
			}()
		}

		containerAttachOpts := types.ContainerAttachOptions{
			Stdin:  true,
			Stdout: true,
			Stderr: true,
			Stream: true,
		}
		hjresp, err := cli.ContainerAttach(ctx, resp.ID, containerAttachOpts)
		if err != nil {
			logger.Println("Error while attaching to container:", err)
			os.Exit(ERR_CONTAINER_ATTACH)
		}
		go ssh.DiscardRequests(reqs)

		for newChannel := range chans {
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel: %v", err)
			}

			go func(in <-chan *ssh.Request) {
				for req := range in {

					switch req.Type {
					case "shell":
						req.Reply(true, nil)
					}
				}
			}(requests)

			startReadChan := make(chan bool)

			go func(w io.WriteCloser) { // Read from terminal and write to container input
				startReadChan <- true // Not sure this is needed anymore, it's just to halt before we

				w.Write(([]byte("\n"))) // Just send a LF to get a prompt at startup

				defer channel.Close()
				for {

					data := make([]byte, 32)
					n, err := channel.Read(data)
					if err != nil {
						logger.Println("SSH Channel read error: ", err)
						cancel()
						break
					}
					inputChan <- data[0]
					if session.inputTimeout > 0 {
						timeoutchan <- true
					}
					if n > 0 {
						if data[0] == 4 { // EOT, we want to catch this to not kill the container
							cancel()
							break
						} else {
							w.Write(data)
						}
					}

				}
			}(hjresp.Conn)

			go func() { // Read output from container and write back to user
				<-startReadChan
				for {
					data, err := hjresp.Reader.ReadByte()
					if err != nil {
						logger.Println("Read error from container output", err)
						cancel()
						break
					}
					channel.Write([]byte{data})
				}
			}()
		}
	}()
	<-rCtx.Done()
	logger.Printf("SSH session ended\n")
	session.TimeEnd = time.Now()
	nConn.Close()

	cli.ContainerPause(ctx, resp.ID)

	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		if debug {
			logger.Printf("Modified file: %s\n", d.Path)
		}
		session.ModifiedFiles = append(session.ModifiedFiles, d.Path)
	}
	logger.Printf("Killing container\n")
	logger.Printf("Writing log\n")
	err = createLog(*session, outputDir)
	if err != nil {
		logger.Println("Error while writing log: ", err)
	}
	err = createJsonLog(*session, outputDir)
	if err != nil {
		logger.Println("Error while writing JSON log: ", err)
	}
	err = cli.ContainerKill(ctx, resp.ID, "SIGKILL")
	if err != nil {
		logger.Println("Error while killing container: ", err)
	}

	if session.PcapEnabled {
		logger.Printf("Getting PCAP data\n")
		ior, _, err := cli.CopyFromContainer(ctx, pcap.ID, "/session.pcap")
		if err != nil {
			logger.Println("Error getting PCAP data: ", err)
		} else {
			defer ior.Close()

			tarReader := tar.NewReader(ior)
			tarReader.Next()
			buf := new(bytes.Buffer)
			buf.ReadFrom(tarReader)

			err = createPCAPFile(*session, outputDir, buf.Bytes())
			if err != nil {
				logger.Println("Error creating PCAP file: ", err)
			}
		}

		logger.Printf("Killing PCAP container\n")
		err = cli.ContainerKill(ctx, pcap.ID, "SIGKILL")
		if err != nil {
			logger.Println("Error while killing container: ", err)
		}
	}

	logger.Println("Removing network.")
	err = cli.NetworkRemove(ctx, networkName)
	if err != nil {
		logger.Println("Warning: error while removing network: ", err)
	}

	logger.Printf("All done\n")

}

func createPCAPFile(session sessionData, outputDir string, pcap []byte) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%d.pcap", session.GlobalId, session.Id)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}
	f.Write(pcap)
	if err != nil {
		return err
	}
	return nil
}

func createJsonLog(session sessionData, outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	jsonBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s-%d.json", session.GlobalId, session.Id)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	f.WriteString(string(jsonBytes))
	if err != nil {
		return err
	}

	return nil
}

func createLog(session sessionData, outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%d", session.GlobalId, session.Id)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	str := fmt.Sprintf("Log for session %d from address '%s'. Image '%s'. Network mode '%s'. Client version: '%s'\n",
		session.Id,
		session.SourceIp,
		session.Image,
		session.NetworkMode,
		session.ClientVersion)
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("Start time: %s (%d)\n", session.TimeStart.Format(time.UnixDate), session.TimeStart.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("End time: %s (%d)\n", session.TimeEnd.Format(time.UnixDate), session.TimeEnd.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = "Session end reason: "
	if session.TimedOutByNoInput {
		str = fmt.Sprintf("%sNo user input.\n", str)
	} else if session.TimedOutBySession {
		str = fmt.Sprintf("%sSession timeout reached.\n", str)
	} else {
		str = fmt.Sprintf("%sConnection closed.\n", str)
	}

	f.WriteString(str)
	if err != nil {
		return err
	}

	f.WriteString("Authentication attempts;\n")
	for i, a := range session.AuthAttempts {
		if a.Successful {
			str = fmt.Sprintf("Accepted attempt %d at %s: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
		} else {
			str = fmt.Sprintf("Rejected attempt %d at %s: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
		}
		f.WriteString(str)
		if err != nil {
			return err
		}
	}

	f.WriteString("User input;\n")
	for _, u := range session.UserInput {
		str := fmt.Sprintf("%s: '%s'\n", u.Time.Format(time.UnixDate), u.Data)
		f.WriteString(str)
		if err != nil {
			return err
		}
	}
	f.WriteString("File modified during session;\n")
	for _, file := range session.ModifiedFiles {
		str := fmt.Sprintf("Path: %s\n", file)
		f.WriteString(str)
		if err != nil {
			return err
		}
	}
	f.WriteString("Log end.\n")

	return nil
}

func authCallBackWrapper(session *sessionData, debug bool, logger log.Logger) func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if debug {
			logger.Printf("(DEBUG) Auth attempt: Username %s, password %s\n", c.User(), string(pass))
		}
		session.SourceIp = c.RemoteAddr().String()
		session.ClientVersion = string(c.ClientVersion())
		a := authAttempt{
			Username: c.User(),
			Password: string(pass),
			Time:     time.Now(),
		}

		if len(session.AuthAttempts) == 2 {
			logger.Println("Accepting connection")
			session.User = c.User()
			session.Password = string(pass)
			a.Successful = true
			session.AuthAttempts = append(session.AuthAttempts, a)
			return nil, nil
		} else {
			session.AuthAttempts = append(session.AuthAttempts, a)
		}
		return nil, fmt.Errorf("(DEBUG) password rejected for %q", c.User())
	}
}

func writeTar(tarWriter *tar.Writer, name string, data []byte) error {

	tarHeader := &tar.Header{
		Name: name,
		Size: int64(len(data)),
	}

	err := tarWriter.WriteHeader(tarHeader)
	if err != nil {
		return err
	}
	_, err = tarWriter.Write(data)
	if err != nil {
		return err
	}
	return nil
}
