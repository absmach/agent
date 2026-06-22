# Copyright (c) Abstract Machines
# SPDX-License-Identifier: Apache-2.0

# Stage 1: Build the UI on the native platform (where npm/native-addons work)
FROM --platform=$BUILDPLATFORM golang:1.26-alpine AS ui
ARG SVC
WORKDIR /go/src/github.com/absmach/agent
RUN apk update && apk add make nodejs npm
COPY Makefile ./
COPY ui/ ./ui/
RUN make ui_prod

# Stage 2: Build the Go binary for the target platform
FROM golang:1.26-alpine AS builder
ARG TARGETOS
ARG TARGETARCH
ARG TARGETPLATFORM
ARG SVC
ARG GOARM
ARG VERSION
ARG COMMIT
ARG TIME

WORKDIR /go/src/github.com/absmach/agent
COPY . .
COPY --from=ui /go/src/github.com/absmach/agent/ui/dist ./ui/dist
RUN apk update && apk add make && \
    GOOS=$TARGETOS GOARCH=$TARGETARCH GOARM=$GOARM \
    go build -ldflags "-s -w \
    -X 'github.com/absmach/agent.BuildTime=$TIME' \
    -X 'github.com/absmach/agent.Version=$VERSION' \
    -X 'github.com/absmach/agent.Commit=$COMMIT'" \
    -o build/magistrala-$SVC cmd/main.go && \
    mv build/magistrala-$SVC /exe

FROM alpine:3.24
# For debugging purposes, socat is installed to create virtual serial ports
RUN apk add socat
COPY --from=builder /exe /
ENTRYPOINT ["/bin/sh", "-c", "socat -d -d pty,raw,echo=0,link=/dev/ttyV0 pty,raw,echo=0,link=/dev/ttyV1 & exec /exe"]
