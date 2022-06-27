package main

const DOCKER_FILE_BASE = "COPY entrypoint.sh /entrypoint.sh\nRUN chmod +x /entrypoint.sh\nENTRYPOINT /entrypoint.sh\n"
const PCAP_DOCKER_FILE = "FROM alpine\nCOPY entrypoint.sh /entrypoint.sh\nRUN apk update && apk add tcpdump && chmod +x /entrypoint.sh\nENTRYPOINT /entrypoint.sh\n"
const PCAP_ENTRYPOINT = "#!/bin/sh\ntcpdump -i any -s 65535 -w /session.pcap\n"
const ENTRYPOINT = "#!/bin/bash\nif [[ \"$USR\" != \"root\" ]]\nthen\nuseradd -m -p thisisfake $USR -s /bin/bash\nsu - $USR\nelse\nbash\nfi\n"
const DOCKER_CLIENT_ENV_NAME = "minipot-client-env:latest"
