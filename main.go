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

	// ch := make(chan string)
	// go func(ch chan string) {
	// 	// disable input buffering
	// 	exec.Command("stty", "-F", "/dev/tty", "cbreak", "min", "1").Run()
	// 	// do not display entered characters on the screen
	// 	exec.Command("stty", "-F", "/dev/tty", "-echo").Run()
	// 	var b []byte = make([]byte, 1)
	// 	for {
	// 		os.Stdin.Read(b)
	// 		ch <- string(b)
	// 	}
	// }(ch)

	// var input string

	// for {
	// 	select {
	// 	case stdin, _ := <-ch:
	// 		//fmt.Printf("Keys pressed: -%s-\n", stdin)
	// 		input = fmt.Sprintf("%s%s", input, stdin)
	// 		if stdin == "\n" {
	// 			fmt.Println("RETURN")
	// 			fmt.Printf(input)
	// 			stdin = ""
	// 		} else if stdin == "\t" {
	// 			fmt.Println("TAB")
	// 		}
	// 		//n, err := os.Stdout.Write([]byte(stdin))
	// 		// if err != nil {
	// 		// 	fmt.Println(err)
	// 		// } else {
	// 		// 	fmt.Println("N:", n)
	// 		// }
	// 		// default:
	// 		// 	fmt.Println("Working..")
	// 	}
	// 	// time.Sleep(time.Millisecond * 100)
	// }

	// fmt.Println("Starting")
	// l, err := net.Listen("tcp4", ":22") // Listen to all addresses on the given port number
	// if err != nil {
	// 	fmt.Println("Error setting up TCP listener:", err)
	// 	os.Exit(1)
	// }
	// defer l.Close()      // Make sure we close everything on exit
	// c, err := l.Accept() // Accept connection on TCP
	// if err != nil {
	// 	fmt.Println("Error getting data on TCP:", err)
	// 	os.Exit(1)
	// }

	// for {

	// 	fmt.Println("Listening")
	// 	reader := bufio.NewReader(c) // Create a reader
	// 	defer c.Close()              // Make sure we close it even if something fails along the way

	// 	r, err := reader.ReadString('\n') // Read first line until newline (recipients)
	// 	if err != nil {
	// 		fmt.Println("TCP read recipient list error:", err)
	// 		return
	// 	}
	// 	fmt.Println(r) // Remove the newline from recipient line

	// }

	// // Public key authentication is done by comparing
	// // the public key of a received connection
	// // with the entries in the authorized_keys file.
	// authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	// if err != nil {
	// 	log.Fatalf("Failed to load authorized_keys, err: %v", err)
	// }

	// authorizedKeysMap := map[string]bool{}
	// for len(authorizedKeysBytes) > 0 {
	// 	pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
	// 	if err != nil {
	// 		log.Fatal(err)
	// 	}

	// 	authorizedKeysMap[string(pubKey.Marshal())] = true
	// 	authorizedKeysBytes = rest
	// }

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	// Once a ServerConfig has been configured, connections can be
	// accepted.

	image := flag.String("image", "docker.io/library/alpine", "Image to use as user environment")
	flag.Parse()

	loggingChannel := make(chan string, 1000)
	logger := log.New(os.Stderr, fmt.Sprintf("%s:\t", "minipot"), log.Ldate|log.Ltime|log.Lshortfile)
	//image := "docker.io/library/alpine"
	go func() {
		for {
			logLine := <-loggingChannel
			logger.Println(logLine)
		}

	}()

	//fmt.Println("SERVER START")
	loggingChannel <- "Starting minipot"
	loggingChannel <- "Connecting to Docker engine"
	ctx := context.Background()
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		panic(err)
	}
	loggingChannel <- fmt.Sprintf("Pulling image %s", image)
	reader, err := cli.ImagePull(ctx, *image, types.ImagePullOptions{})
	if err != nil {
		panic(err)
	}

	// out, err := cli.ContainerLogs(ctx, resp.ID, types.ContainerLogsOptions{ShowStdout: true})
	// if err != nil {
	// 	panic(err)
	// }

	//stdcopy.StdCopy(os.Stdout, os.Stderr, out)

	config := &ssh.ServerConfig{
		// Remove to disable password auth.
		PasswordCallback: func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {
			// Should use constant-time compare (or better, salt+hash) in
			// a production setting.
			// if c.User() == "testuser" && string(pass) == "tiger" {
			// 	return nil, nil
			// }
			loggingChannel <- fmt.Sprintf("Auth attempt: Username %s, password %s\n", c.User(), string(pass))
			//fmt.Println("AUTH: ", c.User(), "/", string(pass))
			if time.Now().Second()%2 == 0 {
				loggingChannel <- "Accepting connection"
				return nil, nil
			}
			return nil, fmt.Errorf("password rejected for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	loggingChannel <- "Serving SSH"
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
		loggingChannel <- fmt.Sprintf("New SSH session (%d)\n", sid)
		go handleClient(nConn, reader, cli, config, loggingChannel, *image, fmt.Sprintf("SESSION%d", sid))
		// term := terminal.NewTerminal(channel, "> ")
		sid++
	}
}

func handleClient(nConn net.Conn, reader io.ReadCloser, cli *client.Client, config *ssh.ServerConfig, loggingChannel chan string, image string, sessionId string) {

	ctx := context.Background()
	///////////////
	fromcont := make(chan ([]byte))
	tocont := make(chan ([]byte))

	// ctx, cancel := context.WithTimeout(context.Background(), time.Duration(time.Second*30))
	// defer cancel()
	newCtx := context.Background()
	rCtx, cancel := context.WithCancel(newCtx)

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
				case <-time.After(15 * time.Second):
					cancel()
				}
			}
		}()
		// fmt.Println("WAIT")
		// statusCh, errCh := cli.ContainerWait(ctx, resp.ID, container.WaitConditionNotRunning)
		// select {
		// case err := <-errCh:
		// 	if err != nil {
		// 		panic(err)
		// 	}
		// case <-statusCh:
		// }
		// fmt.Println("STARTED")

		cattopts := types.ContainerAttachOptions{
			Stdin:  true,
			Stdout: true,
			Stderr: true,
			Stream: true,
		}

		hjresp, err := cli.ContainerAttach(ctx, resp.ID, cattopts)
		if err != nil {
			fmt.Println(err)
			os.Exit(1)
		}

		fmt.Println(hjresp.Conn)

		/////////////
		_, chans, reqs, err := ssh.NewServerConn(nConn, config)
		if err != nil {
			log.Fatal("failed to handshake: ", err)
		}

		go ssh.DiscardRequests(reqs)

		// Service the incoming Channel channel.
		for newChannel := range chans {
			// Channels have a type, depending on the application level
			// protocol intended. In the case of a shell, the type is
			// "session" and ServerShell may be used to present a simple
			// terminal interface.
			if newChannel.ChannelType() != "session" {
				newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
				continue
			}
			channel, requests, err := newChannel.Accept()
			if err != nil {
				log.Fatalf("Could not accept channel: %v", err)
			}

			// Sessions have out-of-band requests such as "shell",
			// "pty-req" and "env".  Here we handle only the
			// "shell" request.
			go func(in <-chan *ssh.Request) {
				for req := range in {
					// fmt.Println("Type:", req.Type)
					// fmt.Println("WR: ", req.WantReply)
					// fmt.Println("PL: ", req.Payload)
					// req.Reply(req.Type == "shell", nil)
					// //req.Reply(req.Type == "pty-req", nil)

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
					//log.Println("Received to send to docker", string(data))
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
					loggingChannel <- fmt.Sprintf("(%s) User input: %s\n", sessionId, line)
					tocont <- []byte(line)
				}
			}()

			go func() {
				for {

					data := <-fromcont
					_, err = term.Write(data)
					if err != nil {
						fmt.Println("Conn write error, ", err)
					} else {
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
					} else {
						fmt.Println("NOP ON READ")
					}
				}
			}()
		}

	}()
	<-rCtx.Done()
	loggingChannel <- fmt.Sprintf("(%s) SSH session ended\n", sessionId)
	nConn.Close()

	//fmt.Println("SAVING STUFF HERE")

	cli.ContainerPause(ctx, resp.ID)

	diffs, err := cli.ContainerDiff(ctx, resp.ID)
	for _, d := range diffs {
		loggingChannel <- fmt.Sprintf("(%s) Modified file: %s\n", sessionId, d.Path)
	}
	loggingChannel <- fmt.Sprintf("(%s) Killing container\n", sessionId)
	err = cli.ContainerKill(ctx, resp.ID, "SIGINT")
	if err != nil {
		fmt.Println("container kill err: ", err)
	} else {
		loggingChannel <- fmt.Sprintf("(%s) All done\n", sessionId)
	}

}
