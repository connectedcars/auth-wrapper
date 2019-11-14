# Auth wrapper

Simple wrapper that exposes an ssh-agent to all sub processes using keys from Google Cloud KMS or OpenSSH pem formated key.

This can fx. be used in CI/CD pipelines when checking code out, running package installers pulling code from private repos.

## How to use

Git clone with key store in Google Cloud KMS:

``` bash
export SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1
auth-wrapper git clone git@github.com:connectedcars/private-module.git
```

Docker buildkit build with a key stored in Google Cloud KMS:

``` bash
export SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1
export PROGRESS_NO_TRUNC=1
export DOCKER_BUILDKIT=1
auth-wrapper docker --progress=plain --ssh=default='$SSH_AUTH_SOCK' .
```

[Dockerfile](./testdata/Dockerfile)

Google Cloud build with Docker buildkit build:

``` yaml
steps:
  # Pull a modern version of docker
  - name: 'gcr.io/cloud-builders/docker'
    args: ['pull', 'gcr.io/cloud-builders/docker:latest']
  # Workaround for https://github.com/moby/moby/issues/39120
  - name: 'gcr.io/cloud-builders/docker'
    args: ['pull', 'docker/dockerfile:experimental']
  - name: 'gcr.io/cloud-builders/docker'
    args: ['pull', 'docker/dockerfile:1.0-experimental']
  # Build container injecting 
  - name: 'gcr.io/$PROJECT_ID/auth-wrapper.master:latest'
    args: ['build', '--progress=plain', '--ssh=default=$$SSH_AUTH_SOCK', '-tag=gcr.io/$PROJECT_ID/$REPO_NAME.$BRANCH_NAME:$COMMIT_SHA', '.']
    env:
      - "SSH_KEY_PATH=kms://projects/connectedcars-staging/locations/global/keyRings/cloudbuilder/cryptoKeys/ssh-key/cryptoKeyVersions/3"
      - "PROGRESS_NO_TRUNC=1"
      - "DOCKER_BUILDKIT=1"
images: ['gcr.io/$PROJECT_ID/$REPO_NAME.$BRANCH_NAME']
```

## Google Cloud KMS


