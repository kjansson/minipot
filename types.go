package main

import "time"

const APP_NAME = "minipot"
const PCAP_IMAGE = "minipot-pcap:latest"

const ERR_FILE_OPEN = 1
const ERR_PRIVATE_KEY_LOAD = 2
const ERR_PRIVATE_KEY_PARSE = 3
const ERR_SSH_SERVE = 4
const ERR_SSH_ACCEPT = 5
const ERR_CONTAINER_ATTACH = 6
const ERR_CONTAINER_CREATE = 7
const ERR_CONTAINER_START = 8
const ERR_CONTAINER_NETWORK_CONNECT = 9
const ERR_DOCKER_INVALID_NETWORK_MODE = 10
const ERR_DOCKER_IMAGE_BUILD = 11
const ERR_DOCKER_ENGINE_CLIENT_CREATE = 12
const ERR_TAR_WRITE_HEADER = 13
const ERR_TAR_WRITE_BODY = 14

type Input struct {
	Data string
	Time time.Time
}

type authAttempt struct {
	Method     string
	Username   string
	Password   string
	Time       time.Time
	Successful bool
}

type sshRequest struct {
	Type    string
	Payload string
}

// Session information, exported values are used in JSON log
type sessionData struct {
	MinipotSessionID     string
	SSHSessionID         int
	User                 string
	Password             string
	GuestEnvHostname     string
	SourceIP             string
	ClientVersion        string
	TimeStart            time.Time
	TimeEnd              time.Time
	AuthAttempts         []authAttempt
	SSHRequests          []sshRequest
	UserInput            []Input
	ModifiedFiles        []string
	ModifiedFilesIgnore  []string
	LoginError           string
	NetworkMode          string
	Image                string
	sessionTimeout       int
	inputTimeout         int
	TimedOutBySession    bool
	TimedOutByNoInput    bool
	environmentVariables []string
	PcapEnabled          bool
	permitAttempt        int
}
