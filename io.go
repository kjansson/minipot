package main

import (
	"log"
	"strconv"
	"strings"

	"github.com/docker/docker/api/types"
	"golang.org/x/crypto/ssh"
)

func handleSSHInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {
	<-startReadChan

	defer channel.Close()
	for {
		data, n, err := readFromSSHChannel(channel, 256) // Read from SSH channel
		if err != nil {
			session.sshSessionCancel()
			break
		}
		if n > 0 {
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
}

func handleContainerInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {

	<-startWriteChan            // Wait for other goroutine to start
	channel.Write([]byte{'\n'}) // Just to force a prompt
	for {
		data, err := hjresp.Reader.ReadByte() // Read output from container
		if err != nil {
			session.minipotSessionCancel()
			break
		}
		channel.Write([]byte{data}) // Forward to SSH channel
	}
}

func handleContainerExecInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {

	<-startWriteChan // Wait for other goroutine to start
	for {
		data, err := ReadFromContainer(hjresp.Reader)
		if err != nil {
			channel.SendRequest("exit-status", false, ssh.Marshal(&exitStatusMessage{0}))
			channel.CloseWrite()
			channel.Close()

			session.sshSessionCancel()
			break

		}
		writeToSSHChannel(data, channel)
	}
}

func handleSSHExecInput(channel ssh.Channel, hjresp types.HijackedResponse, session *sessionData, logger log.Logger, startReadChan chan bool, startWriteChan chan bool, inputChan chan byte) {
	<-startReadChan

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
}
