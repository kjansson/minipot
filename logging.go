package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

func createJsonLog(session sessionData, outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	jsonBytes, err := json.Marshal(session)
	if err != nil {
		return err
	}

	filename := fmt.Sprintf("%s-%d.json", session.GlobalId, session.Id)
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

func createLog(session sessionData, outputDir string) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%d", session.GlobalId, session.Id)
	f, err := os.Create(outputDir + filename)
	if err != nil {
		return err
	}

	str := fmt.Sprintf("Log for session %d from address '%s'. Image '%s'. Network mode '%s'. Client version: '%s'\n",
		session.Id,
		session.SourceIp,
		session.Image,
		session.NetworkMode,
		session.ClientVersion)
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("Start time: %s (%d)\n", session.TimeStart.Format(time.UnixDate), session.TimeStart.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = fmt.Sprintf("End time: %s (%d)\n", session.TimeEnd.Format(time.UnixDate), session.TimeEnd.Unix())
	f.WriteString(str)
	if err != nil {
		return err
	}

	str = "Session end reason: "
	if session.TimedOutByNoInput {
		str = fmt.Sprintf("%sNo user input.\n", str)
	} else if session.TimedOutBySession {
		str = fmt.Sprintf("%sSession timeout reached.\n", str)
	} else {
		str = fmt.Sprintf("%sConnection closed.\n", str)
	}

	f.WriteString(str)
	if err != nil {
		return err
	}

	f.WriteString("Authentication attempts;\n")
	for i, a := range session.AuthAttempts {
		if a.Successful {
			str = fmt.Sprintf("Accepted attempt %d at %s: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
		} else {
			str = fmt.Sprintf("Rejected attempt %d at %s: username: '%s', password '%s'\n", i+1, a.Time.Format(time.UnixDate), a.Username, a.Password)
		}
		f.WriteString(str)
		if err != nil {
			return err
		}
	}

	f.WriteString("User input;\n")
	for _, u := range session.UserInput {
		str := fmt.Sprintf("%s: '%s'\n", u.Time.Format(time.UnixDate), u.Data)
		f.WriteString(str)
		if err != nil {
			return err
		}
	}

	f.WriteString("File modified during session;\n")
	for _, file := range session.ModifiedFiles {
		str := fmt.Sprintf("Path: %s\n", file)
		f.WriteString(str)
		if err != nil {
			return err
		}
	}

	f.WriteString("Log end.\n")

	return nil
}

func createPCAPFile(session sessionData, outputDir string, pcap []byte) error {

	if !strings.HasSuffix(outputDir, "/") {
		outputDir = fmt.Sprintf("%s/", outputDir)
	}

	filename := fmt.Sprintf("%s-%d.pcap", session.GlobalId, session.Id)
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
