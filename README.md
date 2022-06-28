# minipot

Minipot is a simplistic SSH honeypot written in Go leveraging the Docker engine for client environments. It is multi-user, has session control, user interaction logging and packet capture capabilities. It is written with user friendliness in mind, and requires minimal effort to build and run. 

# How does it work?
Minipot is a "fake" SSH server which accepts login with any username and password after a given number of attempts.  
When an attacker is given access, a container is started just for that session. This container is prepared at runtime from a base image of your choice. Keep in mind that the entrypoint will be overwritten, so a standard OS base image is probably most suitable, like Ubuntu or Centos.  
The SSH session is handled by the server itself and input/output is merely forwarded to and from the container, making it appear to the attacker that is actually has a direct SSH session. This also allows for capturing and controlling input and output, and controlling the environment, e.g. setting up a legit user for the accepted session.  
The client session can be configured to timeout after a period of no input, or after a certain amount of time after SSH session starts, to not keep containers/attackers hanging around forever.
SSH client information, origin, authentication attempts, SSH requests, user input and file system changes are logged. There's also a packet capture option.
  
Minipot is dead simple to use. Just an executable to run, while having Docker up and running. It will run just fine without any arguments if you just want to try it out, but you can configure it to you liking if you want. Read more below.

# Requirements
* Docker engine running - https://docs.docker.com/engine/install/
* Go for building binary - https://go.dev/doc/install

# Images
Tested with Ubuntu and Centos. Alpine has some issues and is not recommended at the moment.

# Build
```
go mod tidy
go build
```

# Flags
```
-baseimage      # Image to use as base for user environment build. Entrypoint will be overwritten. Default is "ubuntu:18.04".
-debug          # Set to =true to enable debug output.
-outputdir      # Which path to output session log files to. Defaults to current working directory.
-id             # Global session ID. Used for log file names etc. Defaults to epoch.
-hostname       # Hostname to use in container. Default is container default.
-networkmode    # Docker network mode to use for container. Can be 'none', 'bridge' or 'host'. Defaults to "none". 
-sessiontimeout # Number of seconds before closing a session. Defaults to 1800.
-inputtimeout   # Number of seconds before closing a session if no user input is detected. Zero or less disables timeout. Defaults to 300.
-pcap           # Enables packet capture. Only available when using '-networkmode=bridge'.
-privatekey     # Path to private key for SSH server if providing your own is preferable. If left empty, one will be created for each session.
-bindaddress    # SSH bind address and port in format 'ip:port'. Default is '0.0.0.0:22'.
```

# How to run it
```
# Run with default settings
./minipot

# With some options
./minipot -baseimage centos:centos7 -debug=true -hostname=my-important-server-01 -outputdir=/var/log/minipot -id=tuesday-1 -pcap=true
```
# Packet capture
Packet capture can be enabled by using the flag '-pcap=true'. It will run tcpdump in a separate container attached to the container network of the client (so to be invisible to the client), and PCAP files will be stored along with the regular log files. Be aware that it captures all traffic, which could potentially be CPU-intensive and take up some storage.

# Logging
Logs will be outputted to the chosen path, one text file for readability and one in JSON format.  
Filename format for text logs is '{id}-{ssh-sessionid}', and the same for JSON but with .json as file ending.  
Logs contain information about client, origin, requests, authentication attempts, user input (keystrokes), and files that have been modified during the session. 
PCAP files will be stored (if enabled) with the same filename format as logs, with a .pcap suffix.

# Other information
By default, containers have no network connection. This can be changed using the flag -networkmode, but do so at your own risk. Available modes are "none", "host", and "bridge". Packet capture is only available in bridge mode.
