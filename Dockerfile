ARG WRAP_IMAGE
ARG WRAP_COMMAND
ARG SSH_KEY_PATH

# Build image
FROM gcr.io/cloud-builders/go:latest as builder

ARG VERSION="1.0-dev"

ADD . /app

WORKDIR /app

RUN go version

# Needs access to a google token
#RUN go test ./...

ENV GO111MODULE=on

RUN CGO_ENABLED=0 GOOS=linux go build -o auth-wrapper -ldflags "-X 'main.versionString=$VERSION'" ./cmd

# Production image
FROM ${WRAP_IMAGE} as production

ARG WRAP_COMMAND
ENV WRAP_COMMAND=${WRAP_COMMAND}

ARG SSH_KEY_PATH
ENV SSH_KEY_PATH=${SSH_KEY_PATH}

COPY --from=builder /app/auth-wrapper /opt/auth-wrapper

ENTRYPOINT ["/opt/auth-wrapper"]
