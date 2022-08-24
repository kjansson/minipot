package main

import (
	"context"
	"time"

	"github.com/docker/docker/client"
)

// Session information, exported values are used in JSON log
type sessionData struct {
	minipotSessionContext context.Context
	minipotSessionCancel  context.CancelFunc
	sshSessionContext     context.Context
	sshSessionCancel      context.CancelFunc
	dockerClient          *client.Client
	MinipotSessionID      string
	SSHSessionID          int
	User                  string
	Password              string
	loginSuccessful       bool
	GuestEnvHostname      string // TODO ARRAY
	SourceIP              string
	ClientVersion         string
	Timestamps            []time.Time
	// TimeStart            time.Time
	// TimeEnd              time.Time
	AuthAttempts         []authAttempt
	SSHRequests          []sshRequest
	UserInput            []Input
	ModifiedFiles        []string
	ModifiedFilesIgnore  []string
	LoginError           string
	NetworkMode          string
	Image                string
	containerID          string
	pcapContainerID      string
	networkID            string
	sessionTimeout       int
	inputTimeout         int
	TimedOutBySession    bool
	TimedOutByNoInput    bool
	environmentVariables []string
	PcapEnabled          bool
	permitAttempt        int
}

func (s sessionData) getPasswordAuthAttempts() int {
	attemps := 0
	for _, a := range s.AuthAttempts {
		if a.Method == "password" {
			attemps++
		}
	}
	return attemps
}

func (s sessionData) removeIgnoredModifiedFiles() []string {
	keepFiles := []string{}

	for index, file := range s.ModifiedFiles {
		found := false
		for _, ignore := range s.ModifiedFilesIgnore {
			if file == ignore {
				found = true
			}
		}
		if !found {
			keepFiles = append(keepFiles, s.ModifiedFiles[index])
		}
	}
	return keepFiles
}
