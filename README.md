# minipot

Minipot is a minimalistic SSH honeypot written in Go

# How does it work?
Minipot is a "fake" SSH server which accepts login as root with any password after a certain number of attempts.
When a user is "authenticated", a container is started just for the session. Input/output is forwarded to and from the container. The session can be configured to timeout after a period of no input, or after a certain amount of time since session start, to not keep containers hanging around forever.
Client information, authentication attempts, user input and file system changes are logged.
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
-image          # Which image to run for user sessions. Default is "ubuntu:18.04".
-debug          # Set to =true to enable debug output.
-outputdir      # Which path to output session log files to. Defaults to current working directory.
-id             # Global session ID. Used for log file names etc. Defaults to epoch.
-networkmode    # Docker network mode to use for container. Defaults to "none". Use with caution!
-sessiontimeout # Number of seconds before closing a session. Defaults to 1800.
-inputtimeout   # Number of seconds before closing a session if no user input is detected. Zero or less disables timeout. Defaults to 300.
-envvars        # Environment variables to pass on to container, in the format VAR=val and separated by ','. If you want to do some custom stuff in your container. 

```

# How to run it

```
# Run with default settings
./minipot

# With some options
./minipot -image ubuntu:18.04 -debug=true -hostname=my-important-server-01 -outputdir=/var/log/minipot -id=mysession-1
```

# Session logs
Logs will be outputted to the chosen path, one for each SSH session. It will contain information about authentication attempts, user input (keystrokes), and files that have been modified.

# Other information

By default, containers have no network connection. This can be changed using the flag -networkmode, but do so at your own risk.

# Future improvements
- Allow for other users besides root (needs automatic user creation on startup)
- Allow for multiple images with a random being chosen for a session
- Fix support for Alpine
