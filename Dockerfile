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

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper

ARG WRAP_COMMAND
ENV WRAP_COMMAND=${WRAP_COMMAND}

ARG SSH_KEY_PATH
ENV SSH_KEY_PATH=${SSH_KEY_PATH}

# Used by git image
ENV GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

RUN ln -s /opt/bin/auth-wrapper /opt/bin/${WRAP_COMMAND}
ENV PATH=/opt/bin:${PATH}

ENTRYPOINT ["/opt/auth-wrapper"]
