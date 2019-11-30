# syntax = docker/dockerfile:experimental
FROM ubuntu:19.10 as builder

# Force go tools to use the DNS name so we can overwrite it in docker
ENV GCE_METADATA_HOST=metadata.google.internal
# Used by google python code
#ENV GCE_METADATA_ROOT=metadata.google.internal

# Test ssh key injection
RUN apt-get update -qq && \
	apt-get dist-upgrade -qq -y --no-install-recommends && \
	apt-get install -qq -y --no-install-recommends git openssh-client \
	curl ca-certificates python python3 && \
	rm -rf /var/lib/apt/lists/*

# Install gcloud sdk
RUN curl -sSL https://sdk.cloud.google.com | bash
ENV PATH $PATH:/root/google-cloud-sdk/bin

#RUN curl -s -v -H "Accept-Encoding: identity" -H "Metadata-Flavor: Google" http://metadata.google.internal/computeMetadata/v1/project/numeric-project-id && echo 
#RUN gcloud auth print-access-token
#RUN gsutil -DD ls gs://connectedcars-staging-cloudbuilder-private/

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts

ENV GIT_SSH_COMMAND="ssh -vvvv"

RUN --mount=type=ssh,required=true export && git clone git@github.com:connectedcars/private-module.git
