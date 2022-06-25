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
	username string
	password string
	time     time.Time
}

type sessionData struct {
	id            string
	timeStart     time.Time
	timeEnd       time.Time
	authAttempts  []string
	userInput     []input
	modifiedFiles []string
}

func main() {

	image := flag.String("image", "docker.io/library/alpine", "Image to use as user environment")
	flag.Parse()

	logger := log.New(os.Stderr, fmt.Sprintf("%s:\t", "minipot"), log.Ldate|log.Ltime|log.Lshortfile)

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

	config := &ssh.ServerConfig{
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			logger.Printf("Auth attempt: Username %s, password %s\n", c.User(), string(pass))
			if time.Now().Second()%2 == 0 {
				logger.Println("Accepting connection")
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("fake_id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	logger.Println("Serving SSH")
	listener, err := net.Listen("tcp", "0.0.0.0:22")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}

	sid := 0
	for {

		nConn, err := listener.Accept()
		if err != nil {
			log.Fatal("failed to accept incoming connection: ", err)
		}
		session := sessionData{id: "SESSION-%d"}
		logger.Printf("New SSH session (%s)\n", session.id)
		go handleClient(nConn, reader, cli, config, *image, logger, session)
		sid++
	}
}

func handleClient(nConn net.Conn, reader io.ReadCloser, cli *client.Client, config *ssh.ServerConfig, image string, logger *log.Logger, session sessionData) {

	//var mutex sync.RWMutex
	ctx := context.Background()
	fromcont := make(chan byte)
	tocont := make(chan []byte)

	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	go func() {
		time.Sleep(600 * time.Second) // Container timeout
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
	},
		&container.HostConfig{
			AutoRemove:  true,
			NetworkMode: "none",
		}, nil, nil, "")
	if err != nil {
		panic(err)
	}
	if err := cli.ContainerStart(ctx, resp.ID, types.ContainerStartOptions{}); err != nil {
		panic(err)
	}

	go func() {

		timeoutchan := make(chan bool)
		go func() {
			for {
				select {
				case <-timeoutchan:
				case <-time.After(120 * time.Second): // Make this configurable
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
			log.Fatal("failed to handshake: ", err)
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

			go func() { // READ FROM TERMINAL
				defer channel.Close()
				for {
					data := make([]byte, 1024)
					n, err := channel.Read(data)
					if err != nil {
						logger.Println("SSH Channel read error: ", err)
						cancel()
						break
					}
					if n > 0 {
						if data[0] == 4 { // EOT
							cancel()
							break
						} else {
							logger.Printf("(%s) User input: %x\n", session.id, data[0])
							tocont <- data
						}
					}
				}
			}()

			// Write to docker container
			go func(w io.WriteCloser) { // WRITE TO CONTAINER INPUT
				for {
					data, ok := <-tocont
					if !ok {
						w.Close()
						return
					}
					w.Write(data)
				}
			}(hjresp.Conn)

			go func() { // WRITE OUTPUT TO USER

				for {
					b := <-fromcont
					channel.Write([]byte{b})
				}
			}()

			go func() { // READ OUTPUT FROM CONTAINER
				for {

					data, err := hjresp.Reader.ReadByte()
					if err != nil {
						logger.Println("Read error from container output", err)
						cancel()
						break
					}

					fromcont <- data

				}
			}()
		}

	}()
	<-rCtx.Done()
	logger.Printf("(%s) SSH session ended\n", session.id)
	nConn.Close()

	cli.ContainerPause(ctx, resp.ID)

	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		logger.Printf("(%s) Modified file: %s\n", session.id, d.Path)
	}
	logger.Printf("(%s) Killing container\n", session.id)
	err = cli.ContainerKill(ctx, resp.ID, "SIGINT")
	if err != nil {
		logger.Println("Error while killing container: ", err)
	} else {
		logger.Printf("(%s) All done\n", session.id)
	}
}

func getPrompt(w io.WriteCloser, resp types.HijackedResponse, logger *log.Logger) (string, error) {
	data := []byte("\n")
	n, err := w.Write(data)
	if err != nil {
		return "", err
	}
	logger.Println("WROTE ", n, " BYTES FOR PROMPT")
	prompt, err := resp.Reader.ReadBytes(data[0])
	if err != nil {
		return "", err
	}
	logger.Println("READ ", len(prompt), "BYTES FOR PROMPT")
	return string(prompt), nil
}
