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
	"golang.org/x/crypto/ssh/terminal"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
)

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
		logger.Printf("New SSH session (SESSION-%d)\n", sid)
		go handleClient(nConn, reader, cli, config, *image, logger, fmt.Sprintf("SESSION-%d", sid))
		sid++
	}
}

func handleClient(nConn net.Conn, reader io.ReadCloser, cli *client.Client, config *ssh.ServerConfig, image string, logger *log.Logger, sessionId string) {

	ctx := context.Background()
	fromcont := make(chan ([]byte))
	tocont := make(chan ([]byte))

	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

	go func() {
		time.Sleep(60 * time.Second) // Container timeout
		cancel()
	}()

	defer reader.Close()
	io.Copy(os.Stdout, reader)

	resp, err := cli.ContainerCreate(ctx, &container.Config{
		Image:        image,
		Cmd:          []string{"/bin/sh"},
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
				case <-time.After(15 * time.Second): // Make this configurable
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

			term := terminal.NewTerminal(channel, "/ # ")

			// Write to docker container
			go func(w io.WriteCloser) {
				for {
					data, ok := <-tocont
					if !ok {
						w.Close()
						return
					}
					w.Write(append(data, '\n'))
				}
			}(hjresp.Conn)

			go func() {
				defer channel.Close()
				for {
					line, err := term.ReadLine()
					if err != nil {
						break
					}
					logger.Printf("(%s) User input: %s\n", sessionId, line)
					tocont <- []byte(line)
				}
			}()

			go func() {
				for {

					data := <-fromcont
					_, err = term.Write(data)
					if err == nil {
						timeoutchan <- true
					}
				}
			}()

			go func() {
				delim := []byte("\n")
				for {

					data := []byte{}
					data, err := hjresp.Reader.ReadBytes(delim[0])
					if err == nil && len(data) > 1 {
						fromcont <- data
					}
				}
			}()
		}

	}()
	<-rCtx.Done()
	logger.Printf("(%s) SSH session ended\n", sessionId)
	nConn.Close()

	cli.ContainerPause(ctx, resp.ID)

	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		logger.Printf("(%s) Modified file: %s\n", sessionId, d.Path)
	}
	logger.Printf("(%s) Killing container\n", sessionId)
	err = cli.ContainerKill(ctx, resp.ID, "SIGINT")
	if err != nil {
		logger.Println("Error while killing container: ", err)
	} else {
		logger.Printf("(%s) All done\n", sessionId)
	}
}
