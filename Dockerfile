ARG WRAP_IMAGE
ARG WRAP_COMMAND
ARG SSH_KEY_PATH

# Build image
FROM gcr.io/cloud-builders/go:1.21 AS builder

ARG VERSION="1.0-dev"

ADD . /app

WORKDIR /app

RUN go version

# Needs access to a google token and a ssh client
# RUN go test ./...

ENV GO111MODULE=on

RUN CGO_ENABLED=0 GOOS=linux go build -o auth-wrapper -ldflags "-X 'main.versionString=$VERSION'" ./cmd/authwrapper

RUN echo nobody:x:65534:65534:nobody:/: > password.minimal

#
# Auth-wrapper server image
#
FROM scratch AS main

ARG SSH_KEY_PATH

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper
COPY --from=builder /app/password.minimal /etc/password

USER nobody

ENTRYPOINT ["/opt/bin/auth-wrapper"]

#
# Authwrapped git with KMS keys
#
FROM gcr.io/cloud-builders/git AS git-kms

ARG SSH_KEY_PATH

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper
RUN ln -s /opt/bin/auth-wrapper /opt/bin/git

ENV GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

ENV PATH=/opt/bin:${PATH}
ENV SSH_KEY_PATH=${SSH_KEY_PATH}
ENTRYPOINT ["/opt/bin/git"]


#
# Authwrapped docker with KMS keys
#
FROM gcr.io/cloud-builders/docker AS docker-kms

ARG SSH_KEY_PATH

RUN apt-get update && apt-get install -y --no-install-recommends docker-buildx-plugin && apt-get clean -y && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper
RUN ln -s /opt/bin/auth-wrapper /opt/bin/docker

ENV GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"
RUN echo "Host *\n  StrictHostKeyChecking no" > /etc/ssh/ssh_config.d/01-hostkey-disable.conf

ENV PATH=/opt/bin:${PATH}
ENV SSH_KEY_PATH=${SSH_KEY_PATH}
ENV DOCKER_BUILDKIT=1
ENTRYPOINT ["/opt/bin/docker"]

#
# Authwrapped git with local keys
#
FROM gcr.io/cloud-builders/git AS git-local

COPY --from=builder /app/auth-wrapper /opt/bin/auth-wrapper
RUN ln -s /opt/bin/auth-wrapper /opt/bin/git

COPY build.pem /
RUN chmod 600 /build.pem

ENV GIT_SSH_COMMAND="ssh -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no"

ENV PATH=/opt/bin:${PATH}
ENV SSH_KEY_PATH=/build.pem
ENTRYPOINT ["/opt/bin/git"]
