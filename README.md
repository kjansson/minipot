# minipot

WIP

Minipot is a minimalistic SSH honeypot

# How does it work?
Minipot is a fake SSH server which accepts any user/password combination on random authentication attempts. 
When a user is "authenticated", a container (with no network connection by default) is started just for this session. The attacker is presented with a fake prompt, and input/output is forwarded to and from the container. The session will timeout after a period of no input, or after a certain amount of time since session start, to not keep containers hanging around forever.
All authentication attempts, user input and file system changes are logged.

# Requirements
* Docker engine running

# Build and run
```
go mod tidy
go build
./minipot
```

# Arguments
```
-image # Which image to run for user sessions. Default is "docker.io/library/alpine".
```

# WIP / TODO
* Make prompt look more real
* Global container timeout
* More configuration options
* Support for multiple images