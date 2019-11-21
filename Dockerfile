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
ARG WRAP_NAME
ARG SSH_KEY_PATH

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper
RUN ln -s /opt/bin/auth-wrapper /opt/bin/${WRAP_NAME}

# Used by git image
ENV GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

ENV PATH=/opt/bin:${PATH}
ENV WRAP_COMMAND=${WRAP_COMMAND}
ENV SSH_KEY_PATH=${SSH_KEY_PATH}
ENTRYPOINT ["/opt/bin/auth-wrapper"]
