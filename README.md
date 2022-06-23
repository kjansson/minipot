# minipot

WIP

Minipot is a fake SSH server front which allows entry randomly, and lets an (assumed) attacker have access to an isolated container. 
User input and file system changes are logged.

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