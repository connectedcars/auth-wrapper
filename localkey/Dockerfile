ARG FROM_IMAGE
FROM ${FROM_IMAGE} as production

# Force google tools to use the DNS name so we can overwrite it in docker
ENV GCE_METADATA_HOST=metadata.google.internal

ARG SSH_KEY_PATH=/build.pem
ENV SSH_KEY_PATH=${SSH_KEY_PATH}

COPY build.pem /
RUN chmod 600 /build.pem
