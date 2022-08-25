package main

import (
	"context"
)

// Session information, exported values are used in JSON log
type sessionData struct {
	minipotSessionContext context.Context
	minipotSessionCancel  context.CancelFunc
	sshSessionContext     context.Context
	sshSessionCancel      context.CancelFunc
	MinipotSessionID      string
	ClientSessionId       string
	SSHSessionID          int
	User                  string
	Password              string
	loginSuccessful       bool
	GuestEnvHostname      string
	SourceIP              string
	ClientVersion         string
	ClientSessions        map[string]*sshSessionInfo
	LoginError            string
	NetworkMode           string
	containerID           string
	pcapContainerID       string
	networkID             string
	sessionTimeout        int
	TimedOutBySession     bool
	TimedOutByNoInput     bool
	environmentVariables  []string
	PcapEnabled           bool
	permitAttempt         int
}

type sshSessionInfo struct {
	AuthAttempts        []authAttempt
	SSHRequests         []sshRequest
	UserInput           []Input
	ModifiedFiles       []string
	modifiedFilesIgnore []string
}

func (s sessionData) getPasswordAuthAttempts() int {
	return len(s.ClientSessions[s.ClientSessionId].AuthAttempts)
}

func (s sessionData) removeIgnoredModifiedFiles() []string {
	keepFiles := []string{}

	for index, file := range s.ClientSessions[s.ClientSessionId].ModifiedFiles {
		found := false
		for _, ignore := range s.ClientSessions[s.ClientSessionId].modifiedFilesIgnore {
			if file == ignore {
				found = true
			}
		}
		if !found {
			keepFiles = append(keepFiles, s.ClientSessions[s.ClientSessionId].ModifiedFiles[index])
		}
	}
	return keepFiles
}
