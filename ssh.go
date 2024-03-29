package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"log"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// Wrapper for auth callback function, this is only here so we can save auth attempts in session
func authCallBackWrapper(session *sessionData, sessions map[string]*sessionData, debug bool, logger log.Logger) func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

	return func(c ssh.ConnMetadata, pass []byte) (*ssh.Permissions, error) {

		if debug {
			logger.Printf("(DEBUG) Password auth attempt: Username %s, password %s\n", c.User(), string(pass))
		}

		ip := strings.Split(c.RemoteAddr().String(), ":")
		session.SourceIP = ip[0]

		if _, ok := sessions[session.SourceIP]; !ok {
			if debug {
				logger.Println("New client")
			}
			sessions[session.SourceIP] = session
			session.ClientSessions = make(map[int]*sshSessionInfo)
			session.ClientSessionId = fmt.Sprintf("%s-%d", session.SourceIP, time.Now().Unix())
			session.activeSSHSession = true
			session.ClientVersion = string(c.ClientVersion())

		} else {
			if debug {
				logger.Println("Existing client")
			}
			session = sessions[session.SourceIP]
			session.sshSessionAttemptNumber++
		}
		a := authAttempt{
			Username: c.User(),
			Password: string(pass),
			Time:     time.Now(),
			Method:   "password",
		}

		if _, ok := session.ClientSessions[session.sshSessionAttemptNumber]; !ok {
			session.ClientSessions[session.sshSessionAttemptNumber] = &sshSessionInfo{}
		}

		if session.loginSuccessful {
			if string(pass) == session.Password { // Accept previously used password
				logger.Println("Accepting connection from existing session")
				session.User = c.User()
				session.Password = string(pass)
				a.Successful = true
				session.activeSSHSession = true
				session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts = append(session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts, a)
				return nil, nil
			} else {
				session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts = append(session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts, a)
			}
		} else {
			if session.getPasswordAuthAttempts() == session.permitAttempt-1 { // Permit login
				session.User = c.User()
				session.Password = string(pass)
				a.Successful = true
				logger.Println("Session that fucks up: ", session.sshSessionAttemptNumber)

				session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts = append(session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts, a)
				session.loginSuccessful = true
				return nil, nil
			} else {
				session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts = append(session.ClientSessions[session.sshSessionAttemptNumber].AuthAttempts, a)
			}
		}
		return nil, fmt.Errorf("(DEBUG) password rejected for %q", c.User())
	}
}

func writeToSSHChannel(msg []byte, channel ssh.Channel) error {
	_, err := channel.Write(msg) // Write to SSH channel
	if err != nil {
		return err
	}
	return nil
}

func readFromSSHChannel(channel ssh.Channel, size int) ([]byte, int, error) {
	data := make([]byte, size)
	n, err := channel.Read(data) // Read from SSH channel
	if err != nil && err.Error() != "EOF" {
		return nil, 0, err
	}
	return data[:n], n, nil
}

func createPrivateKey(path string) ([]byte, error) {
	var privateKey []byte
	var err error
	if path != "" { // It needs some kind, either we supply one via file, or we create a new one for each session
		privateKey, err = ioutil.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("failed to read private key: %s", err)
		}
	} else {
		privateKeyGen, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("failed to generate private key: %s", err)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKeyGen),
		})
	}
	return privateKey, nil
}
