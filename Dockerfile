#FROM alpine:3.15
FROM scratch
ADD minipot /
ADD id_rsa /
CMD ["/minipot"]