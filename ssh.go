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
				logger.Println("New session")
			}
			sessions[session.SourceIP] = session

		} else {
			session = sessions[session.SourceIP]
			session.SSHSessionID++
		}
		if !session.loginSuccessful {
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
				session.loginSuccessful = true
				session.SSHSessionID = 0
				return nil, nil
			} else {
				session.AuthAttempts = append(session.AuthAttempts, a)
			}

		} else {
			if debug {
				logger.Println("Existing session")
			}

			session.ClientVersion = string(c.ClientVersion())
			a := authAttempt{
				Username: c.User(),
				Password: string(pass),
				Time:     time.Now(),
				Method:   "password",
			}

			if string(pass) == session.Password { // Accept previously used password
				logger.Println("Accepting connection from existing session")
				session.User = c.User()
				session.Password = string(pass)
				a.Successful = true
				session.AuthAttempts = append(session.AuthAttempts, a)
				return nil, nil
			} else {
				session.AuthAttempts = append(session.AuthAttempts, a)
			}
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
			return nil, fmt.Errorf("Failed to read private key: %s", err)
		}
	} else {
		privateKeyGen, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, fmt.Errorf("Failed to generate private key: %s", err)
		}
		privateKey = pem.EncodeToMemory(&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(privateKeyGen),
		})
	}
	return privateKey, nil
}
