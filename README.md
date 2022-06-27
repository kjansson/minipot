# minipot

Minipot is a minimalistic SSH honeypot written in Go

# How does it work?
Minipot is a "fake" SSH server which accepts login with any username and password after a certain number of attempts.  
When a user is given access, a container is started just for that session. This container is prepared at runtime from a base image of your choice. Keep in mind that the entrypoint will be overwritten, so a standard OS base image is probably most suitable, like Ubuntu or Centos.  
The SSH session is handled by the server and input/output is forwarded to and from the container, making it appear to the client that is actually has a direct SSH session. This also allows for capturing and controlling input and output, and controlling the environment, e.g. setting up a user for the accepted session.
The session can be configured to timeout after a period of no input, or after a certain amount of time after SSH session starts, to not keep containers/attackers hanging around forever.
Client information, authentication attempts, user input and file system changes are logged. Packet capture can be enabled. It will run in a separate container attached to the container network of the client, and PCAP files will be stored along with the normal log files.
It is dead simple to use. Just an executable to run, and have Docker up and running. A single server can host many environments to handle sessions from attackers, how many simply depends on the size of the server and the image used.

# Requirements
* Docker engine running
* Go for building binary

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
-networkmode    # Docker network mode to use for container. Defaults to "none". Use with caution!
-sessiontimeout # Number of seconds before closing a session. Defaults to 1800.
-inputtimeout   # Number of seconds before closing a session if no user input is detected. Zero or less disables timeout. Defaults to 300.
-pcap           # Enables packet capture. 
```

# How to run it

```
# Run with default settings
./minipot

# With some options
./minipot -baseimage centos:centos7 -debug=true -hostname=my-important-server-01 -outputdir=/var/log/minipot -id=mysession-1
```

# Session logs
Logs will be outputted to the chosen path, one file for each SSH session. It will contain information about authentication attempts, user input (keystrokes), and files that have been modified.

# Other information

By default, containers have no network connection. This can be changed using the flag -networkmode, but do so at your own risk. Available modes are "none", "host", and "bridge".  
