FROM golang:1.23-alpine as builder

ENV GO111MODULE=on
RUN apk add --no-cache build-base

WORKDIR /app
COPY . /app
RUN go mod download
RUN GOOS=linux GOARCH=amd64 go build -v -trimpath -ldflags="-s -w" -o /dauthi .
RUN rm -rf /app

FROM alpine:latest

# Release
COPY --from=builder /dauthi /usr/local/bin/dauthi
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
RUN chmod +x /usr/local/bin/dauthi

ENTRYPOINT ["dauthi"]