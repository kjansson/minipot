# Minipot

Minipot is a simple to use SSH honeypot written in Go leveraging the Docker engine for client environments, with user interaction logging and packet capture capabilities. It is written with user friendliness in mind, and requires minimal effort to build and run. 

# How does it work?
Minipot is a fake SSH server which accepts login with any username and password after a given number of attempts.  
When an attacker is given access, a container is started just for that session, and a user environment is created.
Minipot handles the SSH session, and merely forwards input/output to and from the container, making it totally transparent to the attacker while still being in full control of the session and being able to capture input, handle signals, etc.
The container will stay alive for the session duration (which is configurable) and handle subsequent requests for the same client.  
After the session ends, SSH client information, origin, authentication attempts, SSH requests, user input and file system changes are logged. There is also an option to enable packet capture and storing modified files for later examination.

Minipot is aimed at ease of use. Just build and run the image. It will do just fine without any arguments if you just want to try it out, but you can configure it to you liking if you want. Read more below.

# Requirements
* Docker engine running - https://docs.docker.com/engine/install/

# Flags
```
-debug          # Set to =true to enable debug output.
-outputdir      # Which path to output session log files to. Defaults to current working directory.
-id             # Global session ID. Used for log file names etc. Defaults to epoch.
-hostname       # Hostname to use in container. Default is container default.
-networkmode    # Docker network mode to use for container. Can be 'none', 'bridge' or 'host'. Defaults to "none". 
-sessiontimeout # Number of seconds before closing a session. Defaults to 1800.
-pcap           # Enables packet capture. Only available when using '-networkmode=bridge'. Defaults to false.
-privatekey     # Path to private key for SSH server if providing your own is preferable. If left empty, one will be created for each session.
-bindaddress    # SSH bind address and port in format 'ip:port'. Default is '0.0.0.0:22'.
-permitAttempt  # Authentication attempt to permit access to container on. Default is 1.
-savefiles      # Save files modified during session. Creates one tarball with modified files for each SSH session. Defaults to false.
```

# Docker environment variables
When running in Docker, all flags can be set through environment variables with the same name as the flag, but in all caps. E.g. "DEBUG" or "NETWORKMODE".

# How to run it

## Run the binary

Install Go - https://go.dev/doc/install

```
# Build binary
go mod tidy
go build
```

```
# Run with default settings
./minipot

# Or run with some options
./minipot -debug=true -hostname=my-important-server-01 -outputdir=/var/log/minipot -id=tuesday-1 -pcap=true
```

## Run in Docker (recommended)

```
# (Example #1) Run with default settings
docker run -v /var/run/docker.sock:/var/run/docker.sock -p 22:22 kumpe/minipot:latest
```

```
# (Example #2) Or run with some options (custom log output directory, packet capture enabled, custom hostname)
docker run -v /var/run/docker.sock:/var/run/docker.sock -v ./logs:/logs -p 22:22 -e OUTPUTDIR=/logs -e PCAP=true -e HOSTNAME=my-important-server-01 kumpe/minipot:latest
```

# Logging
Logs will be outputted to the chosen path, one text file for human readability and one in JSON format.  
Filename format for text logs is '{id}-{ip}-{ssh-sessionid}', and the same for JSON but with .json as file ending.  
Logs contain information about client, origin, SSH requests, authentication attempts, user input (keystrokes), and files that have been modified during the session. 
PCAP files will be stored (if enabled) with the same filename format as logs, with a .pcap suffix.

# Packet capture
Packet capture can be enabled by using the flag '-pcap=true'. It will run tcpdump in a separate container attached to the container network of the client, and PCAP files will be stored along with the regular log files. Be aware that it captures all traffic, which could potentially be CPU-intensive and eat some storage.
Package capture is only available when using -networkmode=bridge. PCAP files follows the same name schema as logs.

# Modified files
Setting the flag '-savefiles=true' will save all modified files during each SSH session in a tarball. No size limits are enforced, so use with caution. Tarballs follows the same name schema as logs.

# Other information
By default, containers have no network connection. This can be changed using the flag -networkmode, but do so at your own risk. Available modes are "none", "host", and "bridge". Packet capture is only available in bridge mode.
