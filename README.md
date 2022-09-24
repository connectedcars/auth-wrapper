# Auth wrapper

Command wrapper that exposes an ssh-agent to all sub processes with keys and ssh certs backed by Google Cloud KMS or local OpenSSH pem formatted keys.

This can be used in:

* CI/CD pipelines when checking code out, running package installers pulling code from private repos.
* Auditing and restricting access to distributed SSH servers in a central location

# Setup

Add key location to your shell enviroment:

Google KMS hosted key:

``` bash
export SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1
```

Local key:

``` bash
export SSH_KEY_PATH=build.pem
export SSH_KEY_PASSWORD=thepassword
```

# How to use

## SSH login

``` bash
auth-wrapper ssh user@ip
auth-wrapper ssh user@ip 'echo hello'
```

## Git checkout

``` bash
auth-wrapper git clone git@github.com:connectedcars/private-module.git
```

## Docker build

``` bash
auth-wrapper docker build --progress=plain --ssh default .
```

# Advanced

## SSH Certs

Signing server:

The signing server issues a certificate based on an allow list in authorized keys file format:

http://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT

Example file:

authorized_keys:

``` text
# Only allow this public key access from 192.168.1.0/24 and to run command "echo hello" with principal name "user1,serverType"
restrict,command="echo hello",from="192.168.1.0/24",principals="user1,serverType" ecdsa-sha2-nistp256 AAAA...C (copy from output of client) user1@company.com
# Only allow this public key access with principal name "user2"
restrict,principals="user2" ssh-rsa AAAA...D(copy from output of client) user2@company.com
# Only allow sftp access with principal name "user3"
restrict,principals="user3",command=internal-sftp AAAA...E (copy from output of client) user3@company.com
```

Starting the server:

``` bash
export SSH_SIGNING_SERVER_LISTEN_ADDRESS=":3080"
export SSH_CA_KEY_PATH="kms://projects/yourprojectname/locations/global/keyRings/ssh-keys/cryptoKeys/ssh-key/cryptoKeyVersions/1"
export SSH_CA_AUTHORIZED_KEYS_PATH="authorized_keys"
export SSH_SIGNING_LIFETIME="60m"
auth-wrapper
```

Using the client:

``` bash
export SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1
export SSH_SIGNING_SERVER_URL="http://localhost:3080"
auth-wrapper -p user1 ssh 1.2.3.4
auth-wrapper -p serverType:gw ssh 1.2.3.4 # Use wildcard match
```

SSH Server:

To configure a SSH server to trust the signing server CA for a specific user:

~/.ssh/authorized_keys:

``` text
cert-authority,principals="user1,serverType:gw" ssh-rsa AAAA...(copy from output of signing server) ca key
```

# Options

## Arguments

* -principals : Principals to request

## Environment variables

Client options:

* SSH_KEY_PATH: Path to SSH key, can be OpenSSH PEM formated key or a url to KMS key
* SSH_KEY_PASSWORD: Password to key, only used by PEM formated key
* WRAP_COMMAND: Command to run with the arguments to auth-wrapper
* SSH_SIGNING_SERVER_URL: Url for the signing server
* SSH_PRINCIPALS: Principals to request

Signing server options:

* SSH_SIGNING_SERVER_LISTEN_ADDRESS: Listen address in the following format ":8080"
* SSH_CA_KEY_PATH: Path to CA signing key, only KMS keys supported at the moment and limited to "Elliptic Curve P-256 key
SHA256 Digest"
* SSH_CA_AUTHORIZED_KEYS_PATH": Path to authorized_keys following [AUTHORIZED_KEYS_FILE_FORMAT](http://man7.org/linux/man-pages/man8/sshd.8.html#AUTHORIZED_KEYS_FILE_FORMAT)

# Google Cloud KMS key setup

Create keyring and key:

``` bash
# Create keyring
gcloud kms keyrings create --location global ssh-keys
# It needs to be be SHA512 as the ssh client seems to default to this hashing algorithm and KMS pairs key size and hashing algorithms for some reason.
gcloud kms keys create ssh-key --keyring ssh-keys --location global --default-algorithm rsa-sign-pkcs1-4096-sha512 --purpose asymmetric-signing
# Give cloud build access to use the key
gcloud kms keys add-iam-policy-binding ssh-key --keyring=ssh-keys --location=global --member user@company.com --role roles/cloudkms.signerVerifier
```

# Local key

Current the go ssh key implementation does not support the new OpenSSH format so you need to use a PEM formated key:

``` bash
ssh-keygen -f build.key
ssh-keygen -f build.key -m 'PEM' -e > build.pem
```

# Development

## Release new version

``` bash
export GITHUB_TOKEN="YOUR_GH_TOKEN"
git tag -a v2.0.2 -m "Release 2.0.2"
git push origin v2.0.2
goreleaser release --rm-dist
```

## VSCode setup

settings.json
``` json5
{
    // Golang
    "go.useCodeSnippetsOnFunctionSuggest": true,
    "go.useLanguageServer": true,
    "go.alternateTools": {
        "go-languageserver": "gopls"
    },
    "go.buildOnSave": "off",
    "go.vetOnSave": "off",
    "go.useCodeSnippetsOnFunctionSuggestWithoutType": true,
    "go.docsTool": "gogetdoc",
    "editor.codeActionsOnSave": {
        "source.organizeImports": true
    }
}
```

launch.json
``` json5
{
    // Use IntelliSense to learn about possible attributes.
    // Hover to view descriptions of existing attributes.
    // For more information, visit: https://go.microsoft.com/fwlink/?linkid=830387
    "version": "0.2.0",
    "configurations": [
        {
            "name": "Launch",
            "type": "go",
            "request": "launch",
            "mode": "debug",
            "program": "${workspaceFolder}/cmd/authwrapper",
            "env": {
                "SSH_KEY_PATH": "kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1",
                "SSH_SIGNING_SERVER_URL": "http://localhost:3080",
                //"SSH_PRINCIPALS": "tlb",

                "SSH_SIGNING_SERVER_LISTEN_ADDRESS": ":3080",
                "SSH_CA_KEY_PATH": "kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1",
                "SSH_CA_AUTHORIZED_KEYS_PATH": "${workspaceFolder}/authorized_keys",
                "SSH_SIGNING_LIFETIME": "60m",
                
                //"SSH_KEY_PATH": "kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1",
                "GIT_SSH_COMMAND": "ssh -vvvv",
                "DOCKER_BUILDKIT": "1",
                "PROGRESS_NO_TRUNC": "1",
                "SSH_AUTH_SOCK": ""
            },
            "args": [
                "-principals", "tlb",
                //"ssh-add", "-L"
                "ssh", "-p", "22", "-vv", "-l" ,"tlb", "1.2.4.5", "hostname"
                //"bash", "-c", "docker build --no-cache --progress=plain --ssh=default=$SSH_AUTH_SOCK .",
                //"docker", "build", 
                //"--add-host=metadata.google.internal:192.168.65.2", 
                //"--no-cache", 
                //"--progress=plain", 
                //"--ssh=default=$SSH_AUTH_SOCK", 
                //"--build-arg=WRAP_IMAGE=gcr.io/cloud-builders/docker",
                //"--build-arg=WRAP_COMMAND=/usr/bin/docker",
                //"--build-arg=WRAP_NAME=docker",
                //"--build-arg=SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1",
                //"."
                //"git", "clone", "git@github.com:connectedcars/private-module.git"
            ],
            "showLog": true
        },
        {
            "name": "Launch test function",
            "type": "go",
            "request": "launch",
            "mode": "test",
            "program": "${workspaceFolder}/cmd/main_test.go",
            "args": ["-test.timeout", "999s"]
        },
    ]
}
```
