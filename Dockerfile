############################
# STEP 1 build executable binary
############################
# golang alpine 1.15
FROM golang:1.15-alpine as builder

WORKDIR /root

# Install git + SSL ca certificates.
# Git is required for fetching the dependencies.
# Ca-certificates is required to call HTTPS endpoints.
RUN apk update && apk add --no-cache git ca-certificates tzdata && update-ca-certificates

RUN apk update && apk upgrade && \
    apk add --no-cache bash git openssh && \
    apk add --no-cache autoconf automake libtool gettext gettext-dev make g++ texinfo curl && \
    go get github.com/go-delve/delve/cmd/dlv


WORKDIR /home/app/src

