package main

import (
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
	id             int
	globalId       string
	user           string
	password       string
	hostname       string
	sourceIp       string
	clientVersion  string
	timeStart      time.Time
	timeEnd        time.Time
	authAttempts   []authAttempt
	userInput      []input
	modifiedFiles  []string
	networkMode    string
	image          string
	sessionTimeout int
	inputTimeout   int
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

		if len(session.authAttempts) == 2 && c.User() == "root" {
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

func main() {

	image := flag.String("image", "docker.io/library/alpine", "Image to use as user environment.")
	debug := flag.Bool("debug", false, "Enable debug output.")
	outputDir := flag.String("outputdir", "./", "Directory to output session log files to.")
	globalSessionId := flag.String("id", "", "Global session id, for log file names etc. Defaults to epoch.")
	hostname := flag.String("hostname", "", "Hostname to use in container. Default is container default.")
	networkmode := flag.String("networkmode", "none", "Docker network mode to use for containers. Defaults to 'none'. Use with caution!")
	sessionTimeout := flag.Int("sessiontimeout", 1800, "Timeout in seconds before closing a session. Default to 1800.")
	inputTimeout := flag.Int("inputtimeout", 300, "Timeout in seconds before closing a session when no input is detected. Default to 300.")

	flag.Parse()

	logger := log.New(os.Stderr, fmt.Sprintf("%s:\t", "minipot"), log.Ldate|log.Ltime|log.Lshortfile)
	if *globalSessionId == "" {
		tstr := strconv.Itoa(int(time.Now().Unix()))
		globalSessionId = &tstr
	}

	if *networkmode != "none" && *networkmode != "bridge" && *networkmode != "host" && *networkmode != "overlay" && *networkmode != "ipvlan" && *networkmode != "macvlan" {
		logger.Println("No valid network mode given.")
		os.Exit(1)
	}

	logger.Println("Starting minipot")
	logger.Println("Connecting to Docker engine")
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	logger.Printf("Pulling image %s", *image)
	reader, err := cli.ImagePull(ctx, *image, types.ImagePullOptions{})
	if err != nil {
		panic(err)
	}

	privateBytes, err := ioutil.ReadFile("fake_id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	logger.Println("Serving SSH")
	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	sid := 0
	for {
		session := sessionData{
			globalId:       *globalSessionId,
			id:             sid,
			timeStart:      time.Now(),
			hostname:       *hostname,
			networkMode:    *networkmode,
			image:          *image,
			sessionTimeout: *sessionTimeout,
			inputTimeout:   *inputTimeout,
		}

		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}
		config := &ssh.ServerConfig{
			PasswordCallback: authCallBackWrapper(&session, *debug, *logger),
		}

		config.AddHostKey(private)
		logger.Printf("New SSH session (%d)\n", session.id)
		go handleClient(nConn, reader, cli, config, *image, logger, &session, *outputDir, *debug)
		sid++
	}
}

func handleClient(nConn net.Conn, reader io.ReadCloser, cli *client.Client, config *ssh.ServerConfig, image string, logger *log.Logger, session *sessionData, outputDir string, debug bool) {

	ctx := context.Background()

	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	go func() {
		time.Sleep(time.Duration(session.sessionTimeout) * time.Second) // Container timeout
		cancel()
	}()

	defer reader.Close()
	io.Copy(os.Stdout, reader)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        image,
		AttachStderr: true,
		AttachStdin:  true,
		Tty:          true,
		AttachStdout: true,
		OpenStdin:    true,
		Hostname:     session.hostname,
		//Cmd:          []string{"/usr/sbin/useradd", "-p", "thisisfake", "-m", session.user},
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
		go func() {
			for {
				select {
				case <-timeoutchan:
				case <-time.After(time.Duration(session.inputTimeout) * time.Second): // Make this configurable
					cancel()
				}
			}
		}()

		cattopts := types.ContainerAttachOptions{
			Stdin:  true,
			Stdout: true,
			Stderr: true,
			Stream: true,
		}

		hjresp, err := cli.ContainerAttach(ctx, resp.ID, cattopts)
		if err != nil {
			logger.Println("Error while attaching to container:", err)
			os.Exit(1)
		}

		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Println("User failed to login: ", err)
			cancel()
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

				startReadChan <- true

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

	str := fmt.Sprintf("Log for session %d from address %s. Image %s. Network mode %s. \n", session.id, session.sourceIp, session.networkMode, session.image)
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
