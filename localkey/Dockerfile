ARG FROM_IMAGE
FROM ${FROM_IMAGE} as production

ARG SSH_KEY_PATH=/build.pem
ENV SSH_KEY_PATH=${SSH_KEY_PATH}

COPY build.pem /
RUN chmod 600 /build.pem
