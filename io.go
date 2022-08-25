package main

import (
	"fmt"
	"log"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"golang.org/x/crypto/ssh"
)

func handleSSHInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {
	// go func(w io.WriteCloser) { // Read from terminal and write to container input
	<-startReadChan

	// err = WriteToContainer([]byte{'\n'}, hjresp.Conn)
	// if err != nil {
	// 	logger.Println("Error while writing to container:", err)
	// }

	defer channel.Close()
	for {
		fmt.Println("READING FROM SSH")
		data, n, err := readFromSSHChannel(channel, 256) // Read from SSH channel
		if err != nil {
			logger.Println("SSH Channel read error: ", err)
			session.sshSessionCancel()
			break
		}
		if n > 0 {
			fmt.Println("FROM SSH TO CONTAINER: ", data)
			inputChan <- data[0] // Send to input collector for later logging

			if data[0] == 4 { // This is EOT, we want to catch this so client does not kill container
				session.sshSessionCancel() // Instead cancel so we can collect data and cleanup container
				break
			} else {
				WriteToContainer(data, hjresp.Conn) // Forward to container input
			}
		} else {
			break
		}

	}
	// }(hjresp.Conn)
}

func handleContainerInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {

	// go func() { // Read output from container and write back to user
	<-startWriteChan            // Wait for other goroutine to start
	channel.Write([]byte{'\n'}) // Just to force a prompt
	for {
		fmt.Println("READING FROM CONTAINER")
		data, err := hjresp.Reader.ReadByte() // Read output from container
		if err != nil {
			session.minipotSessionCancel()
			break
		}
		fmt.Println("FROM CONTAINER TO SSH: ", data)
		channel.Write([]byte{data}) // Forward to SSH channel
	}
	// }()
}

func handleContainerExecInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {

	// go func() { // Read output from container and write back to user
	<-startWriteChan // Wait for other goroutine to start
	for {
		fmt.Println("READING FROM CONTAINER")

		data, err := ReadFromContainer(hjresp.Reader)
		if err != nil {
			logger.Println("Error while reading from container:", err)
			channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMessage{0}))
			channel.CloseWrite()
			channel.Close()

			session.sshSessionCancel()
			break

		}

		fmt.Println("FROM CONTAINER TO SSH: ", data)
		writeToSSHChannel(data, channel)
	}
	// }()
}

func handleSSHExecInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {
	// go func(w io.WriteCloser) { // Read from terminal and write to container input
	<-startReadChan

	// err = WriteToContainer([]byte{'\n'}, hjresp.Conn)
	// if err != nil {
	// 	logger.Println("Error while writing to container:", err)
	// }
	payloadSize := 256
	var err error
	defer channel.Close()
	for {
		msg, n, rserr := readFromSSHChannel(channel, payloadSize+1)
		if rserr != nil || n == 0 {
			channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMessage{0}))
			channel.CloseWrite()
			channel.Close()
			break
		}

		if n != 0 {
			if string(msg[0]) == "C" { // Copy file, we need to get payload size
				parts := strings.Split(string(msg), " ")
				payloadSize, err = strconv.Atoi(parts[1])
				if err != nil {
					logger.Println("Atoi error, ", err)
				}
			}
		}

		err = WriteToContainer(msg, hjresp.Conn)
		if err != nil {
			logger.Println("Error while writing to container:", err)
		}

	}
	// }(hjresp.Conn)
}
