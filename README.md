# Auth wrapper

Simple wrapper that exposes an ssh-agent to all sub processes using keys from Google Cloud KMS or OpenSSH pem formated key.

This can fx be used in CI/CD pipelines when checking code out, running package installers pulling code from private repos.

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

Git clone with local key:

``` bash
export SSH_KEY_PATH=build.pem
export SSH_KEY_PASSWORD=thepassword
auth-wrapper git clone git@github.com:connectedcars/private-module.git
```

## Google Cloud KMS key setup

Create keyring and key:

``` bash
# Create keyring for cloud build keys
gcloud kms keyrings create --location global cloudbuild
# It needs to be be SHA512 as the ssh client seems to default to this hashing algorithm and KMS pairs key size and hashing algorithms for some reason.
gcloud kms keys create ssh-key --keyring cloudbuilder --location global --default-algorithm rsa-sign-pkcs1-4096-sha512 --purpose asymmetric-signing
# Give cloud build access to use the key
gcloud kms keys add-iam-policy-binding ssh-key --keyring=cloudbuilder --location=global --member serviceAccount:projectserviceaccount@cloudbuild.gserviceaccount.com --role roles/cloudkms.signerVerifier
```

Extract public key and convert to ssh format:

``` bash
gcloud kms keys versions get-public-key 1 --key ssh-key --keyring=cloudbuilder --location=global > ssh-key.pem
# Copy the output to a github user
ssh-keygen -f ssh-key.pem -i -mPKCS8
```

## Local key

Current the go ssh key implementation does not support the new OpenSSH format so you need to use a PEM formated key:

``` bash
ssh-keygen -f build.key
ssh-keygen -f build.key -m 'PEM' -e > build.pem
```
