package main

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
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
	"unicode"

	"golang.org/x/crypto/ssh"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/api/types/network"
	"github.com/docker/docker/client"
)

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
	sshBindAddress := flag.String("bindaddress", "0.0.0.0:22", "SSH bind address and port in format 'ip:port'. Default is '0.0.0.0:22'")
	permitAttempt := flag.Int("permitattempt", 3, "Attempt number to accept connection on. Default is 3.")

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

	if usePcap && (*networkmode == "none" || *networkmode == "host") {
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

		// Build PCAP image
		imageBuildResponse, err := cli.ImageBuild(
			ctx,
			bytes.NewReader(buf.Bytes()),
			types.ImageBuildOptions{
				Context:    bytes.NewReader(buf.Bytes()),
				Dockerfile: "Dockerfile",
				Remove:     true,
				Tags:       []string{PCAP_IMAGE}})
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
		} else { // Read but discard output
			_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
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

	// Build image
	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		bytes.NewReader(buf.Bytes()),
		types.ImageBuildOptions{
			Context:    bytes.NewReader(buf.Bytes()),
			Dockerfile: "Dockerfile",
			Remove:     true,
			Tags:       []string{DOCKER_CLIENT_ENV_NAME}})
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
	} else { // Read but discard output
		_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
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
	listener, err := net.Listen("tcp", *sshBindAddress)
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
			SSHSessionID:     sid,
			MinipotSessionID: *globalSessionId,
			TimeStart:        time.Now(),
			GuestEnvHostname: *hostname,
			NetworkMode:      *networkmode,
			Image:            *baseimage,
			sessionTimeout:   *sessionTimeout,
			inputTimeout:     *inputTimeout,
			PcapEnabled:      usePcap,
			permitAttempt:    *permitAttempt,
		}

		config := &ssh.ServerConfig{
			PasswordCallback: authCallBackWrapper(&session, *debug, *logger),
			AuthLogCallback:  authLogWrapper(&session, *debug, *logger),
		}

		config.AddHostKey(private)
		logger.Printf("New SSH session (%d)\n", session.SSHSessionID)
		go handleClient(nConn, cli, config, &session, *outputDir, *debug)
		sid++
	}
}

func handleClient(nConn net.Conn, cli *client.Client, config *ssh.ServerConfig, session *sessionData, outputDir string, debug bool) {

	logger := log.New(os.Stderr, fmt.Sprintf("%s (session %d): ", APP_NAME, session.SSHSessionID), log.Ldate|log.Ltime|log.Lshortfile)

	ctx := context.Background()
	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	if session.sessionTimeout > 0 { // Session timeout, cancel no matter what when this happens
		if debug {
			logger.Println("Session timeout is set to ", session.sessionTimeout, "seconds.")
		}
		go func() {
			time.Sleep(time.Duration(session.sessionTimeout) * time.Second)
			session.TimedOutBySession = true
			cancel()
		}()
	}

	if debug {
		logger.Println("Creating container.")
	}

	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		if debug {
			log.Println("User failed to login: ", err)
		}
		session.LoginError = err.Error()
		cancel()
	}

	// Create a new Docker network for this session, we don't want containers sharing networks
	networkName := fmt.Sprintf("%s-%d", session.MinipotSessionID, session.SSHSessionID)
	_, err = cli.NetworkCreate(ctx, networkName, types.NetworkCreate{
		Attachable: true,
	})
	if err != nil {
		logger.Println("WARNING: Error while creating network. Might exist already, trying to create container anyway.")
	}

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        DOCKER_CLIENT_ENV_NAME,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		AttachStdout: true,
		OpenStdin:    true,
		Hostname:     session.GuestEnvHostname,
		Env:          append(session.environmentVariables, "USR="+session.User), // This is for the ovveride entrypoint, to create a user
	},
		&container.HostConfig{
			AutoRemove:  true,
			NetworkMode: container.NetworkMode(session.NetworkMode),
		}, nil, nil, "")
	if err != nil {
		logger.Println("Error while creating container: ", err)
		os.Exit(ERR_CONTAINER_CREATE)
	}

	if session.NetworkMode != "none" {
		err = cli.NetworkConnect(ctx, networkName, resp.ID, &network.EndpointSettings{})
		if err != nil {
			logger.Println("Error connecting guest container to network: ", err)
			os.Exit(ERR_CONTAINER_NETWORK_CONNECT)
		}
	}
	err = cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{})
	if err != nil {
		logger.Println("Error while starting container: ", err)
		os.Exit(ERR_CONTAINER_START)
	}
	var pcap = container.ContainerCreateCreatedBody{}
	if session.PcapEnabled {
		inspection, err := cli.ContainerInspect(ctx, resp.ID) // Inspect container so we can get the name
		if err != nil {
			logger.Println("Could not get container inspect:", err)
		}

		name := inspection.Name

		pcap, err = cli.ContainerCreate(ctx, &container.Config{
			Image: PCAP_IMAGE,
		},
			&container.HostConfig{
				AutoRemove:  true,
				NetworkMode: container.NetworkMode("container:" + name), // Connect directly to containers network so stack is shared
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
			// Handle control characters and log them as well
			if b == 127 { // DELETE
				line = fmt.Sprintf("%s<BACKSPACE>", line)
			} else if b == 9 { // TAB
				line = fmt.Sprintf("%s<TAB>", line)
			} else if b == 13 { // CR, create new log line
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

		// Handle input timeout
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

		startReadChan := make(chan bool)

		// Start handling requests
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

					payloadStripControl := strings.Map(func(r rune) rune {
						if unicode.IsPrint(r) {
							return r
						}
						return -1
					}, string(req.Payload))

					if debug {
						logger.Println("New SSH request of type: ", req.Type)
						logger.Println("Request payload: ", payloadStripControl)
						logger.Println("Want reply:", req.WantReply)
					}

					request := sshRequest{
						Type:    req.Type,
						Payload: payloadStripControl,
					}
					session.SSHRequests = append(session.SSHRequests, request)

					switch req.Type {
					case "shell":
						req.Reply(true, nil)
						startReadChan <- true // Pause reading container output, we don't want to read anything before this
					case "exec":
						args := strings.Split(payloadStripControl, " ")

						cResp, err := cli.ContainerExecCreate(ctx, resp.ID, types.ExecConfig{
							User:         session.User,
							Cmd:          args,
							AttachStdout: true,
							AttachStderr: true,
						})
						if err == nil {
							cHjResp, err := cli.ContainerExecAttach(ctx, cResp.ID, types.ExecStartCheck{})
							if err != nil {
								logger.Println("Error while attaching to exec: ", err)
							}
							defer cHjResp.Close()
							data, err := ioutil.ReadAll(cHjResp.Reader)
							if err != nil {
								logger.Println("Error reading from exec attach: ", err)
							}
							// Seriously don't know why I have to slice up this slice, reading from exec attach returns garbage the first bytes
							_, err = channel.Write(data[8:])
							if err != nil {
								logger.Println("Error while writing to SSH channel: ", err)
							}
							channel.Close()
						} else {
							logger.Println("Error while creating exec: ", err)
							err = req.Reply(false, nil)
							if err != nil {
								logger.Println("Error while sending request reply:", err)
							}
						}
					}

				}
			}(requests)

			go func(w io.WriteCloser) { // Read from terminal and write to container input

				defer channel.Close()
				for {
					data := make([]byte, 32)
					n, err := channel.Read(data) // Read from SSH channel
					if err != nil {
						logger.Println("SSH Channel read error: ", err)
						cancel()
						break
					}
					inputChan <- data[0] // Send to input collector for later logging
					if session.inputTimeout > 0 {
						timeoutchan <- true // Send to input timeout handler
					}
					if n > 0 {
						if data[0] == 4 { // This is EOT, we want to catch this so client does not kill container
							cancel() // Instead cancel so we can collect data and cleanup container
							break
						} else {
							w.Write(data) // Forward to container input
						}
					}

				}
			}(hjresp.Conn)

			go func() { // Read output from container and write back to user
				<-startReadChan // Wait for other goroutine to start
				for {
					data, err := hjresp.Reader.ReadByte() // Read output from container
					if err != nil {
						cancel()
						break
					}
					channel.Write([]byte{data}) // Forward to SSH channel
				}
			}()
		}
	}()
	<-rCtx.Done() // Something cancelled
	logger.Printf("SSH session ended\n")
	session.TimeEnd = time.Now()
	nConn.Close()

	if session.PcapEnabled {
		logger.Printf("Getting PCAP data\n")
		ior, _, err := cli.CopyFromContainer(ctx, pcap.ID, "/session.pcap") // Copy PCAP file, comes as TAR archive
		if err != nil {
			logger.Println("WARNING: Error getting PCAP data: ", err)
		} else {
			defer ior.Close()

			// Get data from TAR archive
			tarReader := tar.NewReader(ior)
			tarReader.Next()
			buf := new(bytes.Buffer)
			buf.ReadFrom(tarReader)

			err = createPCAPFile(*session, outputDir, buf.Bytes()) // Create PCAP file in log dir
			if err != nil {
				logger.Println("WARNING: Error creating PCAP file: ", err)
			}
		}
		// Cleanup PCAP
		logger.Printf("Killing PCAP container\n")
		err = cli.ContainerKill(ctx, pcap.ID, "SIGKILL")
		if err != nil {
			logger.Println("Error while killing container: ", err)
		}
	}

	cli.ContainerPause(ctx, resp.ID) // Pause container so we can do diff

	// Save modified file paths
	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		if debug {
			logger.Printf("Modified file: %s\n", d.Path)
		}
		session.ModifiedFiles = append(session.ModifiedFiles, d.Path)
	}

	logger.Printf("Writing log\n")
	err = createLog(*session, outputDir) // Create text log
	if err != nil {
		logger.Println("WARNING: Error while writing log: ", err)
	}
	err = createJsonLog(*session, outputDir) // JSON log
	if err != nil {
		logger.Println("WARNING: Error while writing JSON log: ", err)
	}

	err = cli.ContainerUnpause(ctx, resp.ID) // Must unpause before kill
	if err != nil {
		logger.Println("WARNING: Error while unpausing container.")
	}

	logger.Printf("Killing container\n")
	err = cli.ContainerKill(ctx, resp.ID, "SIGKILL")
	if err != nil {
		logger.Println("WARNING: Error while killing container: ", err)
	}

	logger.Println("Removing network.")
	err = cli.NetworkRemove(ctx, networkName)
	if err != nil {
		logger.Println("WARNING: error while removing network: ", err)
	}

	logger.Printf("All done\n")
}

// Wrapper for auth callback function, this is only here so we can save auth attempts in session
func authCallBackWrapper(session *sessionData, debug bool, logger log.Logger) func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
		if debug {
			logger.Printf("(DEBUG) Password auth attempt: Username %s, password %s\n", c.User(), string(pass))
		}

		ip := strings.Split(c.RemoteAddr().String(), ":")
		session.SourceIP = ip[0]
		session.ClientVersion = string(c.ClientVersion())
		a := authAttempt{
			Username: c.User(),
			Password: string(pass),
			Time:     time.Now(),
			Method:   "password",
		}

		if session.getPasswordAuthAttempts() == session.permitAttempt-1 { // Permit login on third attempt
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

// Wrapper for auth callback, to include login attempts other than password
func authLogWrapper(session *sessionData, debug bool, logger log.Logger) func(c ssh.ConnMetadata, method string, err error) {

	return func(c ssh.ConnMetadata, method string, err error) {
		if method != "password" {
			if debug {
				logger.Printf("(DEBUG) Auth attempt: Username %s, method %s\n", c.User(), method)
			}
			a := authAttempt{
				Username:   c.User(),
				Time:       time.Now(),
				Method:     method,
				Successful: false,
			}
			session.AuthAttempts = append(session.AuthAttempts, a)
		}
		ip := strings.Split(c.RemoteAddr().String(), ":")
		session.SourceIP = ip[0]
		session.ClientVersion = string(c.ClientVersion())
	}
}

func (s sessionData) getPasswordAuthAttempts() int {
	attemps := 0
	for _, a := range s.AuthAttempts {
		if a.Method == "password" {
			attemps++
		}
	}
	return attemps
}
