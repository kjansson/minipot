package main

import (
	"archive/tar"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/docker/docker/client"
)

// Session information, exported values are used in JSON log
type sessionData struct {
	minipotSessionContext   context.Context
	minipotSessionCancel    context.CancelFunc
	sshSessionContext       context.Context
	sshSessionCancel        context.CancelFunc
	MinipotSessionID        string
	ClientSessionId         string
	sshSessionAttemptNumber int
	activeSSHSession        bool
	User                    string
	Password                string
	loginSuccessful         bool
	GuestEnvHostname        string
	SourceIP                string
	ClientVersion           string
	ClientSessions          map[int]*sshSessionInfo
	LoginError              string
	NetworkMode             string
	containerID             string
	pcapContainerID         string
	networkID               string
	sessionTimeout          int
	TimedOutBySession       bool
	environmentVariables    []string
	PcapEnabled             bool
	permitAttempt           int
	saveAlteredFiles        bool
}

type sshSessionInfo struct {
	AuthAttempts        []authAttempt
	SSHRequests         []sshRequest
	UserInput           []Input
	ModifiedFiles       []string
	modifiedFilesIgnore []string
}

func (s sessionData) getPasswordAuthAttempts() int {

	attempts := 0
	for _, attempt := range s.ClientSessions {
		for _, auth := range attempt.AuthAttempts {
			if auth.Method == "password" {
				attempts++
			}
		}
	}
	return attempts
}

func (s sessionData) removeIgnoredModifiedFiles() []string {
	keepFiles := []string{}

	for index, file := range s.ClientSessions[s.sshSessionAttemptNumber].ModifiedFiles {
		found := false
		for _, ignore := range s.ClientSessions[s.sshSessionAttemptNumber].modifiedFilesIgnore {
			if file == ignore {
				found = true
			}
		}
		if !found {
			keepFiles = append(keepFiles, s.ClientSessions[s.sshSessionAttemptNumber].ModifiedFiles[index])
		}
	}
	return keepFiles
}

func (s sessionData) createJsonLog(outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	jsonBytes, err := json.Marshal(s)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s-%s.json", s.MinipotSessionID, s.ClientSessionId)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	f.WriteString(string(jsonBytes))
	if err != nil {
		return err
	}

	return nil
}

func (s sessionData) createLog(outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%s", s.MinipotSessionID, s.ClientSessionId)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	str := fmt.Sprintf("Log for session %s from address '%s'. Network mode '%s'. Client version: '%s'\n",
		s.ClientSessionId,
		s.SourceIP,
		s.NetworkMode,
		s.ClientVersion)
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = "Session end reason: "
	if s.TimedOutBySession {
		str = fmt.Sprintf("%sSession ended by server due to timeout.\n", str)
	} else {
		str = fmt.Sprintf("%sConnection closed by client.\n", str)
	}

	f.WriteString(str)
	if err != nil {
		return err
	}

	keys := make([]int, 0)
	for k, _ := range s.ClientSessions {
		keys = append(keys, k)
	}
	sort.Ints(keys)

	for _, sessionIndex := range keys {
		str = fmt.Sprintf("\nAttempt %d:\n", sessionIndex)
		f.WriteString(str)
		f.WriteString("Authentication attempts;\n")
		for i, a := range s.ClientSessions[sessionIndex].AuthAttempts {
			if a.Method == "password" {
				if a.Successful {
					str = fmt.Sprintf("Accepted attempt %d at %s using password method: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
				} else {
					str = fmt.Sprintf("Rejected attempt %d at %s using password method: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
				}
			} else {
				str = fmt.Sprintf("Rejected attempt %d at %s: username using method %s: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Method, a.Username, a.Password)
			}
			f.WriteString(str)
			if err != nil {
				return err
			}
		}

		str = ""
		f.WriteString("SSH requests;\n")
		for _, r := range s.ClientSessions[sessionIndex].SSHRequests {
			str = fmt.Sprintf("SSH request: Type '%s', payload '%s'\n", r.Type, r.Payload)
		}
		f.WriteString(str)
		if err != nil {
			return err
		}
		str = ""
		f.WriteString("User input;\n")
		for _, u := range s.ClientSessions[sessionIndex].UserInput {
			str := fmt.Sprintf("%s: '%s'\n", u.Time.Format(time.UnixDate), u.Data)
			f.WriteString(str)
			if err != nil {
				return err
			}
		}
		str = ""
		f.WriteString("File modified during session;\n")
		for _, file := range s.ClientSessions[sessionIndex].ModifiedFiles {
			str := fmt.Sprintf("Path: %s\n", file)
			f.WriteString(str)
			if err != nil {
				return err
			}
		}
	}

	f.WriteString("Log end.\n")

	return nil
}

func (s sessionData) createPCAPFile(outputDir string, pcap []byte) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}
	filename := fmt.Sprintf("%s-%s.pcap", s.MinipotSessionID, s.ClientSessionId)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}
	f.Write(pcap)
	if err != nil {
		return err
	}
	return nil
}

func (s sessionData) createModifiedFilesTar(cli *client.Client) error {
	cli.ContainerPause(context.Background(), s.containerID) // Pause container so we can do diff
	filename := fmt.Sprintf("%s-%s-%d.tar", s.MinipotSessionID, s.ClientSessionId, s.sshSessionAttemptNumber)

	file, err := os.Create(filename)
	if err != nil {
		cli.ContainerUnpause(context.Background(), s.containerID) // Unpause container
		return fmt.Errorf("error while creating TAR file: %s", err.Error())
	}
	defer file.Close()

	tarWriter := tar.NewWriter(file)
	defer tarWriter.Close()

	for _, path := range s.ClientSessions[s.sshSessionAttemptNumber].ModifiedFiles {
		file, src, err := cli.CopyFromContainer(context.Background(), s.containerID, path) // Copy PCAP file, comes as TAR archive
		if err != nil {
			cli.ContainerUnpause(context.Background(), s.containerID) // Unpause container
			return errors.New(fmt.Sprintf("Could not copy from container: ", err))
		}

		tr := tar.NewReader(file)
		tr.Next()

		contents, err := ioutil.ReadAll(tr)
		if err != nil {
			return errors.New(fmt.Sprintf("Could not read: %s", err))
		}

		header := &tar.Header{
			Name:    src.Name,
			Size:    int64(len(contents)),
			Mode:    int64(src.Mode),
			ModTime: src.Mtime,
		}
		err = tarWriter.WriteHeader(header)
		if err != nil {
			cli.ContainerUnpause(context.Background(), s.containerID) // Unpause container
			return fmt.Errorf("could not write header for file, got error '%s'", err.Error())
		}

		_, err = tarWriter.Write(contents)
		if err != nil {
			cli.ContainerUnpause(context.Background(), s.containerID) // Unpause container
			return fmt.Errorf("could not copy the file data to the tarball, got error '%s'", err.Error())
		}

	}
	cli.ContainerUnpause(context.Background(), s.containerID) // Unpause container
	return nil
}
