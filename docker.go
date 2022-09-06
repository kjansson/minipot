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
RUN apt update && apt install -y ssh iputils-ping curl wget net-tools
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
		fmt.Errorf("error writing Dockerfile to tarball: %s", err)
	}
	err = writeTar(tarWriter, "entrypoint.sh", []byte(PCAP_ENTRYPOINT))
	if err != nil {
		fmt.Errorf("error writing entrypoint.sh to tarball: %s", err)
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
		fmt.Errorf("error building PCAP image: %s", err)
	}
	defer imageBuildResponse.Body.Close()
	// Read but discard output
	_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
	if err != nil {
		fmt.Errorf("error reading PCAP image build output: %s", err)
	}

	return nil
}

func buildPotContainer(ctx context.Context, cli *client.Client, logger log.Logger) error {
	buf := new(bytes.Buffer)
	tarWriter := tar.NewWriter(buf)

	logger.Println("Starting image build from ", BASE_IMAGE)

	err := writeTar(tarWriter, "Dockerfile", []byte("FROM "+BASE_IMAGE+"\n"+DOCKER_FILE_BASE))
	if err != nil {
		return fmt.Errorf("error writing Dockerfile to tarball: %s", err)
	}
	err = writeTar(tarWriter, "entrypoint.sh", []byte(ENTRYPOINT))
	if err != nil {
		return fmt.Errorf("error writing entrypoint.sh to tarball: %s", err)
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
		return fmt.Errorf("error building image: %s", err)
	}
	defer imageBuildResponse.Body.Close()

	_, err = io.Copy(ioutil.Discard, imageBuildResponse.Body)
	if err != nil {
		return fmt.Errorf("error reading image build output: %s", err)
	}

	return nil
}

func getContainerFileDiff(cli *client.Client, containerID string, logger log.Logger, debug bool) ([]string, error) {
	cli.ContainerPause(context.Background(), containerID) // Pause container so we can do diff

	modifiedFiles := []string{}
	// Save modified file paths
	diffs, err := cli.ContainerDiff(context.Background(), containerID)
	if err != nil {
		cli.ContainerUnpause(context.Background(), containerID) // Unpause container

		return nil, fmt.Errorf("error while getting diffs: %s", err)
	} else {
		for _, d := range diffs {
			modifiedFiles = append(modifiedFiles, d.Path)
		}
	}
	cli.ContainerUnpause(context.Background(), containerID) // Unpause container

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
	b := make([]byte, 20000000) // Should be enough for receiving stuff over scp
	n, err := reader.Read(b)    // Read output from container
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if b[0] == 1 { // Header indicates that is is from stdout. 2 == stderr.
		return []byte(b[8:n]), nil
	} else {
		return nil, errors.New("not from container stdout")
	}

}
