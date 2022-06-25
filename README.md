# minipot

WIP

Minipot is a minimalistic SSH honeypot

# How does it work?
Minipot is a fake SSH server which accepts login as root with any password after a certain number of attempts. 
When a user is "authenticated", a container (with no network connection by default) is started just for this session. The attacker is presented with a fake prompt, and input/output is forwarded to and from the container. The session will timeout after a period of no input, or after a certain amount of time since session start, to not keep containers hanging around forever.
All authentication attempts, user input and file system changes are logged.

# Requirements
* Docker engine running
* Go for building binary

# Build
```
go mod tidy
go build
```

# Flags
```
-image          # Which image to run for user sessions. Default is "docker.io/library/alpine".
-debug          # Set to =true to enable debug output.
-outputdir      # Which path to output session log files to. Defaults to current working directory.
-id             # Global session ID. Used for log file names etc. Defaults to epoch.
-networkmode    # Docker network mode to use for container. Defaults to "none". Use with caution!
-sessiontimeout # Number of seconds before closing a session.
-inputtimeout   # Number of seconds before closing a session if no user input is detected.

```

# How to run it
```
# Default settings
./minipot

# With some options
./minipot -image ubuntu:18.04 -debug=true -outputdir=/var/log/minipot -id=mysession-1
```

# Session logs
Logs will be outputted to the chosen path, one for each SSH session. It will contain information about authentication attempts, user input (keystrokes), and files that have been modified.