#!/bin/bash

CGO_ENABLED=0 go build -ldflags="-s"
upx -9 minipot


docker build --no-cache -t minipot:latest .
