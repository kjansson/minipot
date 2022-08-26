FROM golang:1.19.0-buster as build


WORKDIR /minipot
ADD *.go /minipot
ADD go.mod /minipot
RUN cd /minipot && go mod tidy && CGO_ENABLED=0 go build -o minipot


FROM alpine:3.16.2
RUN apk --no-cache add bash
COPY --from=build /minipot/minipot /minipot
COPY /entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh
ENTRYPOINT ["/entrypoint.sh"]
