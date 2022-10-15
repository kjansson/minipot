package main

import (
	"archive/tar"
	"bytes"
	"context"
	"flag"
	"fmt"
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
	debug := flag.Bool("debug", false, "Enable debug output.")
	outputDir := flag.String("outputdir", "./", "Directory to output session log files to.")
	globalSessionId := flag.String("id", "", "Global session id, for log file names etc. Defaults to epoch.")
	hostname := flag.String("hostname", "", "Hostname to use in container. Default is container default.")
	networkmode := flag.String("networkmode", "none", "Docker network mode to use for containers. Valid options are 'none', 'bridge' or 'host'. Defaults to 'none'. Use with caution!")
	sessionTimeout := flag.Int("sessiontimeout", 1800, "Timeout in seconds before closing a session. Default to 1800.")
	pcapEnabled := flag.Bool("pcap", false, "Enable packet capture. Could potentially use up a lot of disk space.")
	privateKeyFile := flag.String("privatekey", "", "Path to private key for SSH server if providing your own is preferable. If left empty, one will be created for each session.")
	sshBindAddress := flag.String("bindaddress", "0.0.0.0:22", "SSH bind address and port in format 'ip:port'. Default is '0.0.0.0:22'")
	permitAttempt := flag.Int("permitattempt", 1, "Attempt number to accept connection on. Default is to accept on first.")
	saveAlteredFiles := flag.Bool("savefiles", false, "Save altered files. Will create one tarball per SSH session. Defaults to false")

	flag.Parse()

	logger := log.New(os.Stderr, fmt.Sprintf("%s: ", APP_NAME), log.Ldate|log.Ltime|log.Lshortfile)
	if *globalSessionId == "" {
		tstr := strconv.Itoa(int(time.Now().Unix()))
		globalSessionId = &tstr
	}

	sessions := make(map[string]*sessionData)

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
		logger.Println("Error while creating Docker engine client: ", err)
		os.Exit(ERR_DOCKER_ENGINE_CLIENT_CREATE)
	}

	if usePcap {
		err := buildPCAPContainer(ctx, cli, *logger)
		if err != nil {
			logger.Println("Error while building packet capture container: ", err)
			os.Exit(ERR_DOCKER_IMAGE_BUILD)
		}
	}

	err = buildPotContainer(ctx, cli, *logger)
	if err != nil {
		logger.Println("Error while building pot container: ", err)
		os.Exit(ERR_DOCKER_IMAGE_BUILD)
	}

	logger.Println("Build complete")

	privateKey, err := createPrivateKey(*privateKeyFile)
	if err != nil {
		logger.Println("Error while loading or generating private key: ", err)
		os.Exit(ERR_PRIVATE_KEY_GETORCREATE)
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

	for {

		nConn, err := listener.Accept()
		if err != nil {
			logger.Println("SSH accept failed: ", err)
			os.Exit(ERR_SSH_ACCEPT)
		}

		session := sessionData{
			MinipotSessionID: *globalSessionId,
			GuestEnvHostname: *hostname,
			NetworkMode:      *networkmode,
			sessionTimeout:   *sessionTimeout,
			PcapEnabled:      usePcap,
			permitAttempt:    *permitAttempt,
			saveAlteredFiles: *saveAlteredFiles,
		}

		config := &ssh.ServerConfig{
			PasswordCallback: authCallBackWrapper(&session, sessions, *debug, *logger),
		}

		config.AddHostKey(private)
		logger.Println("New SSH session")
		go handleClient(nConn, cli, config, &session, sessions, *outputDir, *debug)
	}
}

func handleClient(nConn net.Conn, cli *client.Client, config *ssh.ServerConfig, session *sessionData, sessions map[string]*sessionData, outputDir string, debug bool) {

	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		if debug {
			log.Println("User failed to login: ", err)
		}
		session.LoginError = err.Error()
		session = sessions[session.SourceIP]
	} else {

		session = sessions[session.SourceIP]
		id := session.sshSessionAttemptNumber

		logger := log.New(os.Stderr, fmt.Sprintf("%s (session %s-%s-%d): ", APP_NAME, session.MinipotSessionID, session.ClientSessionId, session.sshSessionAttemptNumber), log.Ldate|log.Ltime|log.Lshortfile)

		session.minipotSessionContext, session.minipotSessionCancel = context.WithTimeout(context.Background(), time.Duration(session.sessionTimeout)*time.Second)
		newCtx := context.Background()
		session.sshSessionContext, session.sshSessionCancel = context.WithCancel(newCtx)

		go func() {
			time.Sleep(time.Duration(session.sessionTimeout) * time.Second)
			session.sshSessionCancel()
			session.minipotSessionCancel()
		}()

		// If container ID is set in session, there should be a container running with that ID.
		// Resume container and attach to it.
		if session.containerID == "" {
			if debug {
				logger.Println("Creating container.")
			}
			// Create a new Docker network for this session, we don't want containers sharing networks
			session.networkID = fmt.Sprintf("%s-%s", session.MinipotSessionID, session.ClientSessionId)
			_, err = cli.NetworkCreate(context.Background(), session.networkID, types.NetworkCreate{
				Attachable: true,
			})
			if err != nil {
				logger.Println("WARNING: Error while creating network. Might exist already, trying to create container anyway.")
			}

			resp, err := cli.ContainerCreate(context.Background(), &container.Config{
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

			session.containerID = resp.ID

			if session.NetworkMode != "none" {
				err = cli.NetworkConnect(context.Background(), session.networkID, session.containerID, &network.EndpointSettings{})
				if err != nil {
					logger.Println("Error connecting guest container to network: ", err)
					os.Exit(ERR_CONTAINER_NETWORK_CONNECT)
				}
			}
			err = cli.ContainerStart(context.Background(), session.containerID, types.ContainerStartOptions{})
			if err != nil {
				logger.Println("Error while starting container: ", err)
				os.Exit(ERR_CONTAINER_START)
			}
			var pcap = container.ContainerCreateCreatedBody{}

			if session.PcapEnabled {
				inspection, err := cli.ContainerInspect(context.Background(), session.containerID) // Inspect container so we can get the name
				if err != nil {
					logger.Println("Could not get container inspect:", err)
				}

				name := inspection.Name

				pcap, err = cli.ContainerCreate(context.Background(), &container.Config{
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

				err = cli.ContainerStart(context.Background(), pcap.ID, types.ContainerStartOptions{})
				if err != nil {
					logger.Println("Error while starting container: ", err)
					os.Exit(ERR_CONTAINER_START)
				}
				session.pcapContainerID = pcap.ID
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
					session.ClientSessions[id].UserInput = append(session.ClientSessions[id].UserInput, i)
					line = ""
				} else {
					line = fmt.Sprintf("%s%s", line, string(b))
				}
			}
		}()

		go func() {

			// Save modified file paths
			diffs, err := getContainerFileDiff(cli, session.containerID, *logger, debug)
			if err != nil {
				logger.Println("Error while getting diffs: ", err)
			} else {
				for _, path := range diffs {
					session.ClientSessions[session.sshSessionAttemptNumber].modifiedFilesIgnore = append(session.ClientSessions[session.sshSessionAttemptNumber].modifiedFilesIgnore, path)
				}
			}

			if debug {
				logger.Println("Attaching to container")
			}
			containerAttachOpts := types.ContainerAttachOptions{
				Stdin:  true,
				Stdout: true,
				Stderr: true,
				Stream: true,
			}
			cHjResp, err := cli.ContainerAttach(context.Background(), session.containerID, containerAttachOpts)
			if err != nil {
				logger.Println("Error while attaching to container:", err)
				os.Exit(ERR_CONTAINER_ATTACH)
			}
			go ssh.DiscardRequests(reqs)

			startReadChan := make(chan bool) // These are here to pause reading and writing until we have a shell session, we don't want to read on exec
			startWriteChan := make(chan bool)

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
					//Requestloop:
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
						session.ClientSessions[session.sshSessionAttemptNumber].SSHRequests = append(session.ClientSessions[session.sshSessionAttemptNumber].SSHRequests, request)
						switch req.Type {
						case "shell":
							req.Reply(true, nil)
							go handleContainerInput(channel, cHjResp, session, *logger, startReadChan, startWriteChan, inputChan)
							go handleSSHInput(channel, cHjResp, session, *logger, startReadChan, startWriteChan, inputChan)
							startReadChan <- true  // Pause reading container output, we don't want to read anything before this
							startWriteChan <- true // Pause writing to container, we don't want to write anything before this

						case "exec":
							args := strings.Split(payloadStripControl, " ")

							cResp, err := cli.ContainerExecCreate(context.Background(), session.containerID, types.ExecConfig{
								User:         session.User,
								Cmd:          args,
								AttachStdout: true,
								AttachStderr: false,
								AttachStdin:  true,
								Detach:       false,
								Tty:          false,
							})
							if err == nil {

								execResp, err := cli.ContainerExecAttach(context.Background(), cResp.ID, types.ExecStartCheck{})
								if err != nil {
									logger.Println("Error while attaching to exec: ", err)
								}
								req.Reply(true, nil)
								go handleContainerExecInput(channel, execResp, session, *logger, startReadChan, startWriteChan, inputChan)
								go handleSSHExecInput(channel, execResp, session, *logger, startReadChan, startWriteChan, inputChan)
								startReadChan <- true  // Pause reading container output, we don't want to read anything before this
								startWriteChan <- true // Pause writing to container, we don't want to write anything before this
							} else {
								logger.Println("Error while creating exec: ", err)
								err = req.Reply(false, nil)
								if err != nil {
									logger.Println("Error while sending request reply:", err)
								}
							}
						default:
							logger.Println("Unknown request: ", req.Type)
						}

					}
				}(requests)

			}
		}()

		<-session.sshSessionContext.Done() // Something cancelled the SSH session
		session.activeSSHSession = false
		logger.Printf("SSH session ended\n")

		// Save modified file paths
		diffs, err := getContainerFileDiff(cli, session.containerID, *logger, debug)
		if err != nil {
			logger.Println("Error while getting diffs: ", err)
		} else {
			session.ClientSessions[session.sshSessionAttemptNumber].ModifiedFiles = append(session.ClientSessions[session.sshSessionAttemptNumber].ModifiedFiles, diffs...)
		}
		session.ClientSessions[session.sshSessionAttemptNumber].ModifiedFiles = session.removeIgnoredModifiedFiles()

		if session.saveAlteredFiles {
			logger.Println("Saving modified files.")
			err = session.createModifiedFilesTar(cli)
			if err != nil {
				logger.Println("Error while creating modified files tar: ", err)
			}
		}

		<-session.minipotSessionContext.Done() // Wait for minipot session to end
		if id == 0 {
			logger.Printf("Writing log\n")
			err = session.createLog(outputDir) // Create text log
			if err != nil {
				logger.Println("WARNING: Error while writing log: ", err)
			}
			err = session.createJsonLog(outputDir) // JSON log
			if err != nil {
				logger.Println("WARNING: Error while writing JSON log: ", err)
			}
			if debug {
				logger.Printf("Waiting for Minipot session end before killing container.\n")
			}
			if debug {
				logger.Printf("Minipot session ended, cleaning up.\n")
			}

			// TODO all this needs to be done in separate files for each session
			if session.PcapEnabled {
				logger.Printf("Getting PCAP data\n")
				ior, _, err := cli.CopyFromContainer(context.Background(), session.pcapContainerID, "/session.pcap") // Copy PCAP file, comes as TAR archive
				if err != nil {
					logger.Println("WARNING: Error getting PCAP data: ", err)
				} else {
					defer ior.Close()

					// Get data from TAR archive
					tarReader := tar.NewReader(ior)
					tarReader.Next()
					buf := new(bytes.Buffer)
					buf.ReadFrom(tarReader)

					err = session.createPCAPFile(outputDir, buf.Bytes()) // Create PCAP file in log dir
					if err != nil {
						logger.Println("WARNING: Error creating PCAP file: ", err)
					}
				}
				// Cleanup PCAP
				logger.Printf("Killing PCAP container\n")
				err = cli.ContainerKill(context.Background(), session.pcapContainerID, "SIGKILL")
				if err != nil {
					logger.Println("Error while killing container: ", err)
				}
			}

			err = cli.ContainerKill(context.Background(), session.containerID, "SIGKILL")
			if err != nil {
				logger.Println("WARNING: Error while killing container: ", err)
			}

			logger.Println("Removing network.")
			err = cli.NetworkRemove(context.Background(), session.networkID)
			if err != nil {
				logger.Println("WARNING: error while removing network: ", err)
			}
			delete(sessions, session.SourceIP)
		}
	}
	nConn.Close()

	log.Printf("All done\n")
}
