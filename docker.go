package main

const DOCKER_FILE_BASE = `
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh
`

const PCAP_DOCKER_FILE = `
FROM alpine
COPY entrypoint.sh /entrypoint.sh
RUN apk update && apk add tcpdump && chmod +x /entrypoint.sh
ENTRYPOINT /entrypoint.sh
`
const PCAP_ENTRYPOINT = `
#!/bin/sh
tcpdump -i any -s 65535 -w /session.pcap
`
const ENTRYPOINT = `
#!/bin/bash
if [[ \"$USR\" != \"root\" ]]
then
	useradd -m -p thisisfake $USR -s /
	bin/bash
	su - $USR
else
	bash
fi
`
const DOCKER_CLIENT_ENV_NAME = "minipot-client-env:latest"
