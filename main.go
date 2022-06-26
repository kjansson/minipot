package main

import (
	"archive/tar"
	"bytes"
	"context"
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
	"github.com/docker/docker/client"
)

const DOCKER_FILE_BASE = "COPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\nENTRYPOINT /entrypoint.sh\n"
const ENTRYPOINT = "#!/bin/bash\nif [[ \"$USR\" != \"root\" ]]\nthen\nuseradd -m -p thisisfake $USR -s /bin/bash\nsu - $USR\nelse\nbash\nfi\n"

const ERR_IMAGE_PULL = 1
const ERR_PRIVATE_KEY_LOAD = 2
const ERR_PRIVATE_KEY_PARSE = 3
const ERR_SSH_SERVE = 4
const ERR_SSH_ACCEPT = 5
const ERR_CONTAINER_ATTACH = 6
const ERR_DOCKER_INVALID_NETWORK_MODE = 7

type input struct {
	data string
	time time.Time
}

type authAttempt struct {
	username   string
	password   string
	time       time.Time
	successful bool
}

type sessionData struct {
	id                   int
	globalId             string
	user                 string
	password             string
	hostname             string
	sourceIp             string
	clientVersion        string
	timeStart            time.Time
	timeEnd              time.Time
	authAttempts         []authAttempt
	userInput            []input
	modifiedFiles        []string
	networkMode          string
	image                string
	sessionTimeout       int
	inputTimeout         int
	timedOutBySession    bool
	timedOutByNoInput    bool
	environmentVariables []string
	// authSignal           chan bool
}

func main() {
	baseimage := flag.String("baseimage", "ubuntu:18.04", "Image to use as base for user environment. Entrypoint will be overwritten.")
	debug := flag.Bool("debug", false, "Enable debug output.")
	outputDir := flag.String("outputdir", "./", "Directory to output session log files to.")
	globalSessionId := flag.String("id", "", "Global session id, for log file names etc. Defaults to epoch.")
	hostname := flag.String("hostname", "", "Hostname to use in container. Default is container default.")
	networkmode := flag.String("networkmode", "none", "Docker network mode to use for containers. Valid options are 'none', 'bridge' or 'host'. Defaults to 'none'. Use with caution!")
	sessionTimeout := flag.Int("sessiontimeout", 1800, "Timeout in seconds before closing a session. Default to 1800.")
	inputTimeout := flag.Int("inputtimeout", 300, "Timeout in seconds before closing a session when no input is detected. Default to 300.")
	// envVars := flag.String("envvars", "", "Environment variables to pass on to container, in the format VAR=val and separated by ','. If you want to do some custom stuff in your container.")

	image := "minipot-ubuntu:1"
	//imageParts := strings.Split(*imageflag, ":")

	flag.Parse()

	logger := log.New(os.Stderr, fmt.Sprintf("%s:\t", "minipot"), log.Ldate|log.Ltime|log.Lshortfile)
	if *globalSessionId == "" {
		tstr := strconv.Itoa(int(time.Now().Unix()))
		globalSessionId = &tstr
	}

	// environmentVariables := strings.Split(*envVars, ",")

	// for _, x := range environmentVariables {
	// 	logger.Println("ENV:", x)
	// }

	if *networkmode != "none" &&
		*networkmode != "bridge" &&
		*networkmode != "host" {
		logger.Println("No valid network mode given.")
		os.Exit(ERR_DOCKER_INVALID_NETWORK_MODE)
	}

	logger.Println("Starting minipot")
	logger.Println("Connecting to Docker engine")
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	// logger.Printf("Pulling image %s", image)
	// reader, err := cli.ImagePull(ctx, image, types.ImagePullOptions{})
	// if err != nil {
	// 	logger.Println("Failed to pull image: ", err)
	// 	os.Exit(ERR_IMAGE_PULL)
	// }

	buf := new(bytes.Buffer)
	tw := tar.NewWriter(buf)

	logger.Println("build")
	readDockerFile := []byte("FROM " + *baseimage + "\n" + DOCKER_FILE_BASE)

	tarHeader := &tar.Header{
		Name: "Dockerfile",
		Size: int64(len(readDockerFile)),
	}
	err = tw.WriteHeader(tarHeader)
	if err != nil {
		log.Fatal(err, " :unable to write tar header")
	}
	_, err = tw.Write(readDockerFile)
	if err != nil {
		log.Fatal(err, " :unable to write tar body")
	}

	tarHeader = &tar.Header{
		Name: "entrypoint.sh",
		Size: int64(len([]byte(ENTRYPOINT))),
	}
	err = tw.WriteHeader(tarHeader)
	if err != nil {
		log.Fatal(err, " :unable to write tar header")
	}
	_, err = tw.Write([]byte(ENTRYPOINT))
	if err != nil {
		log.Fatal(err, " :unable to write tar body")
	}

	dockerFileTarReader := bytes.NewReader(buf.Bytes())

	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		dockerFileTarReader,
		types.ImageBuildOptions{
			Context:    dockerFileTarReader,
			Dockerfile: "Dockerfile",
			Remove:     true,
			Tags:       []string{"minipot-client-env:latest"}})
	if err != nil {
		log.Fatal(err, " :unable to build docker image")
	}
	defer imageBuildResponse.Body.Close()
	_, err = io.Copy(os.Stdout, imageBuildResponse.Body)
	if err != nil {
		log.Fatal(err, " :unable to read image build response")
	}
	logger.Println("build done")

	//
	//
	//
	privateBytes, err := ioutil.ReadFile("fake_id_rsa")
	if err != nil {
		logger.Println("Failed to load private key: ", err)
		os.Exit(ERR_PRIVATE_KEY_LOAD)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
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
			globalId:       *globalSessionId,
			id:             sid,
			timeStart:      time.Now(),
			hostname:       *hostname,
			networkMode:    *networkmode,
			image:          image,
			sessionTimeout: *sessionTimeout,
			inputTimeout:   *inputTimeout,
			// environmentVariables: environmentVariables,
			// authSignal: make(chan bool),
		}

		config := &ssh.ServerConfig{
			PasswordCallback: authCallBackWrapper(&session, *debug, *logger),
		}

		config.AddHostKey(private)
		logger.Printf("New SSH session (%d)\n", session.id)
		go handleClient(nConn, cli, config, logger, &session, *outputDir, *debug)
		sid++
	}
}

func handleClient(nConn net.Conn, cli *client.Client, config *ssh.ServerConfig, logger *log.Logger, session *sessionData, outputDir string, debug bool) {

	ctx := context.Background()

	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	if session.sessionTimeout > 0 {
		if debug {
			logger.Println("Session timeout is set to ", session.sessionTimeout, "seconds.")
		}
		go func() {
			time.Sleep(time.Duration(session.sessionTimeout) * time.Second) // Container timeout
			session.timedOutBySession = true
			cancel()
		}()
	}

	// defer reader.Close()
	// io.Copy(os.Stdout, reader)
	////<-session.authSignal

	if debug {
		logger.Println("Creating container.")
	}

	_, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Println("User failed to login: ", err)
		cancel()
	}
	//	session.authSignal <- true

	// // Create a temp container to determine default cmd
	// temp, err := cli.ContainerCreate(ctx, &container.Config{
	// 	Image:        session.image,
	// 	AttachStderr: true,
	// 	AttachStdin:  true,
	// 	Tty:          true,
	// 	AttachStdout: true,
	// 	OpenStdin:    true,
	// 	Hostname:     session.hostname,
	// 	Env:          session.environmentVariables,
	// },
	// 	&container.HostConfig{
	// 		AutoRemove:  true,
	// 		NetworkMode: container.NetworkMode(session.networkMode),
	// 	}, nil, nil, "")
	// if err != nil {
	// 	panic(err)
	// }
	// ci, err := cli.ContainerInspect(ctx, temp.ID)
	// if err != nil {
	// 	fmt.Println("nope")
	// }
	// cmd := ci.Config.Cmd
	// cli.ContainerRemove(ctx, ci.ID, types.ContainerRemoveOptions{})
	// if err != nil {
	// 	logger.Println("Warning! Could not remove temporary container.")
	// }

	// // useradd -m -p <encryptedPassword> -s /bin/bash <user>

	// newCmd := strslice.StrSlice([]string{"useradd", "-m", "-p", "thisisfake", session.user, "&&", "su", session.user, "&&"})
	// for _, s := range cmd {
	// 	newCmd = append(newCmd, s)
	// }

	// logger.Println("New cmd: ", newCmd)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        "minipot-client-env:latest",
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		AttachStdout: true,
		OpenStdin:    true,
		Hostname:     session.hostname,
		Env:          append(session.environmentVariables, "USR="+session.user),
	},
		&container.HostConfig{
			AutoRemove:  true,
			NetworkMode: container.NetworkMode(session.networkMode),
		}, nil, nil, "")
	if err != nil {
		panic(err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
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
				i := input{
					data: line,
					time: time.Now(),
				}
				session.userInput = append(session.userInput, i)
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
						session.timedOutByNoInput = true
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
	logger.Printf("(%d) SSH session ended\n", session.id)
	session.timeEnd = time.Now()
	nConn.Close()

	cli.ContainerPause(ctx, resp.ID)

	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		if debug {
			logger.Printf("(%d) Modified file: %s\n", session.id, d.Path)
		}
		session.modifiedFiles = append(session.modifiedFiles, d.Path)
	}
	logger.Printf("(%d) Killing container\n", session.id)
	logger.Println("Writing log")
	createLog(*session, outputDir)
	err = cli.ContainerKill(ctx, resp.ID, "SIGINT")
	if err != nil {
		logger.Println("Error while killing container: ", err)
	} else {
		logger.Printf("(%d) All done\n", session.id)
	}
}

func createLog(session sessionData, outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%d", session.globalId, session.id)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	str := fmt.Sprintf("Log for session %d from address '%s'. Image '%s'. Network mode '%s'. Client version: '%s'\n",
		session.id,
		session.sourceIp,
		session.image,
		session.networkMode,
		session.clientVersion)
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("Start time: %s (%d)\n", session.timeStart.Format(time.UnixDate), session.timeStart.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("End time: %s (%d)\n", session.timeEnd.Format(time.UnixDate), session.timeEnd.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = "Session end reason: "
	if session.timedOutByNoInput {
		str = fmt.Sprintf("%sNo user input.\n", str)
	} else if session.timedOutBySession {
		str = fmt.Sprintf("%sSession timeout reached.\n", str)
	} else {
		str = fmt.Sprintf("%sConnection closed.\n", str)
	}

	f.WriteString(str)
	if err != nil {
		return err
	}

	f.WriteString("Authentication attempts;\n")
	for i, a := range session.authAttempts {
		if a.successful {
			str = fmt.Sprintf("Accepted attempt %d at %s: username: '%s', password '%s'\n", i+1, a.time.Format(time.UnixDate), a.username, a.password)
		} else {
			str = fmt.Sprintf("Rejected attempt %d at %s: username: '%s', password '%s'\n", i+1, a.time.Format(time.UnixDate), a.username, a.password)
		}
		f.WriteString(str)
		if err != nil {
			return err
		}
	}

	f.WriteString("User input;\n")
	for _, u := range session.userInput {
		str := fmt.Sprintf("%s: '%s'\n", u.time.Format(time.UnixDate), u.data)
		f.WriteString(str)
		if err != nil {
			return err
		}
	}
	f.WriteString("File modified during session;\n")
	for _, file := range session.modifiedFiles {
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
		session.sourceIp = c.RemoteAddr().String()
		session.clientVersion = string(c.ClientVersion())
		a := authAttempt{
			username: c.User(),
			password: string(pass),
			time:     time.Now(),
		}

		if len(session.authAttempts) == 2 {
			logger.Println("Accepting connection")
			session.user = c.User()
			session.password = string(pass)
			a.successful = true
			session.authAttempts = append(session.authAttempts, a)
			return nil, nil
		} else {
			session.authAttempts = append(session.authAttempts, a)
		}
		return nil, fmt.Errorf("(DEBUG) password rejected for %q", c.User())
	}
}
