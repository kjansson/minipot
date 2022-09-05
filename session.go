package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
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
	//if _, ok := s.ClientSessions[s.sshSessionID]; ok {
	for _, attempt := range s.ClientSessions {
		for _, auth := range attempt.AuthAttempts {
			if auth.Method == "password" {
				attempts++
			}
		}
	}
	//}
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

	str := fmt.Sprintf("Log for session %d from address '%s'. Network mode '%s'. Client version: '%s'\n",
		s.sshSessionAttemptNumber,
		s.SourceIP,
		s.NetworkMode,
		s.ClientVersion)
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = "Session end reason: "
	if s.TimedOutBySession {
		str = fmt.Sprintf("%sSession timeout reached.\n", str)
	} else {
		str = fmt.Sprintf("%sConnection closed.\n", str)
	}

	f.WriteString(str)
	if err != nil {
		return err
	}

	for sessionIndex, session := range s.ClientSessions {

		str = fmt.Sprintf("\nSession %d:\n", sessionIndex)
		f.WriteString(str)
		f.WriteString("Authentication attempts;\n")
		for i, a := range session.AuthAttempts {
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
		for _, r := range session.SSHRequests {
			str = fmt.Sprintf("SSH request: Type '%s', payload '%s'\n", r.Type, r.Payload)
		}
		f.WriteString(str)
		if err != nil {
			return err
		}
		str = ""
		f.WriteString("User input;\n")
		for _, u := range session.UserInput {
			str := fmt.Sprintf("%s: '%s'\n", u.Time.Format(time.UnixDate), u.Data)
			f.WriteString(str)
			if err != nil {
				return err
			}
		}
		str = ""
		f.WriteString("File modified during session;\n")
		for _, file := range session.ModifiedFiles {
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
