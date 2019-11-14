# Build image
FROM gcr.io/cloud-builders/go:latest as builder

ARG VERSION="1.0-dev"

ADD . /app

WORKDIR /app

RUN go version

# Needs access to a google token
#RUN go test ./...

ENV GO111MODULE=on

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-X 'main.versionString=$VERSION'" ./cmd

# Production image
FROM gcr.io/cloud-builders/docker as production

ARG SSH_KEY_PATH=/build.pem

WORKDIR /app

COPY --from=builder /app/cmd /opt/auth-wrapper

COPY build.pem /
RUN chmod 600 /build.pem

ENV SSH_KEY_PATH=${SSH_KEY_PATH}

ENTRYPOINT [ "/opt/auth-wrapper", "docker" ]
