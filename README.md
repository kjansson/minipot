# minipot

Minipot is a simple to use SSH honeypot written in Go leveraging the Docker engine for client environments. It is multi-user, has session control, user interaction logging and packet capture capabilities. It is written with user friendliness in mind, and requires minimal effort to build and run. 

# How does it work?
Minipot is a fake/modified SSH server which accepts login with any username and password after a given number of attempts.  
When an attacker is given access, a container is started just for that session. The container is ubuntu:18.04 at the moment.
The SSH session is handled by the server itself and input/output is merely forwarded to and from the container, making it appear to the attacker that is actually has a direct SSH session. This also allows for capturing and controlling input and output, and controlling the environment, e.g. setting up a legit user for the accepted session. 
The client session can be configured to timeout after a certain amount of time after SSH session starts, to not keep containers/attackers hanging around forever. 
SSH client information, origin, authentication attempts, SSH requests, user input and file system changes are logged. There's also a packet capture option.
  
Minipot is dead simple to use. Just an executable to run, while having Docker up and running. It will run just fine without any arguments if you just want to try it out, but you can configure it to you liking if you want. Read more below.

# Requirements
* Docker engine running - https://docs.docker.com/engine/install/
* Go for building binary - https://go.dev/doc/install

# Build
```
go mod tidy
go build
```

# Flags
```
-debug          # Set to =true to enable debug output.
-outputdir      # Which path to output session log files to. Defaults to current working directory.
-id             # Global session ID. Used for log file names etc. Defaults to epoch.
-hostname       # Hostname to use in container. Default is container default.
-networkmode    # Docker network mode to use for container. Can be 'none', 'bridge' or 'host'. Defaults to "none". 
-sessiontimeout # Number of seconds before closing a session. Defaults to 1800.
-pcap           # Enables packet capture. Only available when using '-networkmode=bridge'.
-privatekey     # Path to private key for SSH server if providing your own is preferable. If left empty, one will be created for each session.
-bindaddress    # SSH bind address and port in format 'ip:port'. Default is '0.0.0.0:22'.
```

# How to run it
```
# Run with default settings
./minipot

# With some options
./minipot -debug=true -hostname=my-important-server-01 -outputdir=/var/log/minipot -id=tuesday-1 -pcap=true
```
# Packet capture
Packet capture can be enabled by using the flag '-pcap=true'. It will run tcpdump in a separate container attached to the container network of the client (so to be invisible to the client), and PCAP files will be stored along with the regular log files. Be aware that it captures all traffic, which could potentially be CPU-intensive and eat some storage.
Package capture is only available when using -networkmode=bridge

# Logging
Logs will be outputted to the chosen path, one text file for human readability and one in JSON format.  
Filename format for text logs is '{id}-{ssh-sessionid}', and the same for JSON but with .json as file ending.  
Logs contain information about client, origin, requests, authentication attempts, user input (keystrokes), and files that have been modified during the session. 
PCAP files will be stored (if enabled) with the same filename format as logs, with a .pcap suffix.

# Other information
By default, containers have no network connection. This can be changed using the flag -networkmode, but do so at your own risk. Available modes are "none", "host", and "bridge". Packet capture is only available in bridge mode.
