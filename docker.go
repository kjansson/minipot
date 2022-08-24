package main

import (
	"archive/tar"
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
)

const DOCKER_FILE_BASE = `COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
RUN apt update && apt install -y ssh
ENTRYPOINT /entrypoint.sh
`

const PCAP_DOCKER_FILE = `FROM alpine
COPY entrypoint.sh /entrypoint.sh
RUN apk update && apk add tcpdump && chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh
`

const PCAP_ENTRYPOINT = `#!/bin/sh
tcpdump -i any -s 65535 -w /session.pcap
`

const ENTRYPOINT = `#!/bin/bash
if [[ "$USR" != "root" ]]
then
useradd -m -p thisisfake $USR -s /bin/bash
su - $USR
else
bash
fi
`
const DOCKER_CLIENT_ENV_NAME = "minipot-client-env:latest"

func buildPCAPContainer(ctx context.Context, cli *client.Client, logger log.Logger) error {

	// Create tarball with Dockerfile and entrypoint for PCAP image
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)

	logger.Println("Starting PCAP image build")

	err := writeTar(tarWriter, "Dockerfile", []byte(PCAP_DOCKER_FILE))
	if err != nil {
		fmt.Errorf("Error writing Dockerfile to tarball: %s", err)
	}
	err = writeTar(tarWriter, "entrypoint.sh", []byte(PCAP_ENTRYPOINT))
	if err != nil {
		fmt.Errorf("Error writing entrypoint.sh to tarball: %s", err)
	}

	// Build PCAP image
	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		bytes.NewReader(buf.Bytes()),
		types.ImageBuildOptions{
			Context:    bytes.NewReader(buf.Bytes()),
			Dockerfile: "Dockerfile",
			Remove:     true,
			Tags:       []string{PCAP_IMAGE}})
	if err != nil {
		fmt.Errorf("Error building PCAP image: %s", err)
	}
	defer imageBuildResponse.Body.Close()
	// Read but discard output
	_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
	if err != nil {
		fmt.Errorf("Error reading PCAP image build output: %s", err)
	}

	return nil
}

func buildPotContainer(ctx context.Context, cli *client.Client, logger log.Logger, baseimage string) error {
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)

	logger.Println("Starting image build from ", baseimage)

	err := writeTar(tarWriter, "Dockerfile", []byte("FROM "+baseimage+"\n"+DOCKER_FILE_BASE))
	if err != nil {
		return fmt.Errorf("Error writing Dockerfile to tarball: %s", err)
	}
	err = writeTar(tarWriter, "entrypoint.sh", []byte(ENTRYPOINT))
	if err != nil {
		return fmt.Errorf("Error writing entrypoint.sh to tarball: %s", err)
	}

	// Build image
	imageBuildResponse, err := cli.ImageBuild(
		ctx,
		bytes.NewReader(buf.Bytes()),
		types.ImageBuildOptions{
			Context:    bytes.NewReader(buf.Bytes()),
			Dockerfile: "Dockerfile",
			Remove:     true,
			Tags:       []string{DOCKER_CLIENT_ENV_NAME}})
	if err != nil {
		return fmt.Errorf("Error building image: %s", err)
	}
	defer imageBuildResponse.Body.Close()

	_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
	if err != nil {
		return fmt.Errorf("Error reading image build output: %s", err)
	}

	return nil
}

func getContainerFileDiff(cli *client.Client, ctx context.Context, containerID string, logger log.Logger, debug bool) ([]string, error) {
	err := cli.ContainerPause(ctx, containerID) // Pause container so we can do diff
	if err != nil {
		//return nil, fmt.Errorf("error while pausing container: %s", err)
		logger.Println("error while pausing container: ", err)
	}

	modifiedFiles := []string{}
	// Save modified file paths
	diffs, err := cli.ContainerDiff(ctx, containerID)
	if err != nil {
		err = cli.ContainerUnpause(ctx, containerID) // Unpause container
		if err != nil {
			return nil, fmt.Errorf("error while unpausing container: %s", err)
		}
		return nil, fmt.Errorf("error while getting diffs: %s", err)
	} else {
		for _, d := range diffs {
			modifiedFiles = append(modifiedFiles, d.Path)
		}
	}
	err = cli.ContainerUnpause(ctx, containerID) // Unpause container
	if err != nil {
		return nil, fmt.Errorf("error while unpausing container: %s", err)
	}

	return modifiedFiles, nil
}

func WriteToContainer(msg []byte, conn net.Conn) error {

	_, err := conn.Write(msg)               // Write to container
	if err != nil && err.Error() != "EOF" { // Error while writing to container
		return err
	}
	return nil
}

func ReadFromContainer(reader *bufio.Reader) ([]byte, error) {
	fmt.Println("Reading from container")
	b := make([]byte, 1024)
	n, err := reader.Read(b) // Read output from container
	if err != nil {
		return nil, err
	}
	// fmt.Println("Read from container:", string(b[:n]))
	// fmt.Println("Read from container (raw):", b[:n])
	// fmt.Printf("Read %d bytes\n", n)
	if b[0] == 1 {
		// fmt.Println("STDOUT")
		// fmt.Println("Payload is ", string(b[8:n]))
		return []byte(b[8:n]), nil
	} else {
		// fmt.Println("STDERR")
		return nil, errors.New("Not from container stdout")
	}

}
