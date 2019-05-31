############################
# STEP 1 build executable binary
############################
# golang alpine 1.12
FROM golang@sha256:8cc1c0f534c0fef088f8fe09edc404f6ff4f729745b85deae5510bfd4c157fb2 as builder

# Install git + SSL ca certificates.
# Git is required for fetching the dependencies.
# Ca-certificates is required to call HTTPS endpoints.
# build-base contains among other things gcc and libc required to compile ethereum library that contains some code in C.
RUN apk update && apk add --no-cache git ca-certificates tzdata build-base && update-ca-certificates

# Create appuser
RUN adduser -D -g '' appuser

WORKDIR $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/
COPY . .

# Fetch dependencies if we decide to remove the vendor directory at some point
# RUN go get -d -v

WORKDIR $GOPATH/src/0xacab.org/jstuczyn/CoconutGo/daemon/eth-watcher/

# Build the binary
# for production: removes debug, etc. 
# RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-w -s" -a -installsuffix cgo -o /go/bin/eth_watcher .
RUN go build -o /go/bin/eth_watcher . 

# ############################
# # STEP 2 build a small image
# ############################
# FROM scratch - go back to it once we don't need any additional binaries
FROM alpine

LABEL maintainer="Jedrzej Stuczynski"

# Import from builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd

# Copy our static executable 
COPY --from=builder /go/bin/eth_watcher /app/eth_watcher

# Use an unprivileged user.
USER appuser

ENTRYPOINT [ "/app/eth_watcher" ]
