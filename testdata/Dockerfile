# syntax = docker/dockerfile:experimental
FROM ubuntu as builder

# Test ssh key injection
RUN apt-get update -qq && \
	apt-get dist-upgrade -qq -y --no-install-recommends && \
	apt-get install -qq -y --no-install-recommends git openssh-client && \
	rm -rf /var/lib/apt/lists/*

RUN mkdir -p -m 0600 ~/.ssh && ssh-keyscan github.com >> ~/.ssh/known_hosts

RUN --mount=type=ssh,required=true export && git clone git@github.com:connectedcars/private-module.git
