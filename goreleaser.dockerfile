FROM alpine:latest
COPY dauthi /dauthi
ENTRYPOINT ["/dauthi"]