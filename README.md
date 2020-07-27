# Auth wrapper

Command wrapper that exposes an ssh-agent to all sub processes with keys and ssh certs backed by Google Cloud KMS or local OpenSSH pem formatted keys.

This can be used in:

* CI/CD pipelines when checking code out, running package installers pulling code from private repos.
* Auditing and restricting access to distributed SSH servers in a central location

## How to use

### Git checkout

Git clone with key store in Google Cloud KMS:

``` bash
export SSH_KEY_PATH=kms://projects/yourprojectname/locations/global/keyRings/yourkeyring/cryptoKeys/ssh-key/cryptoKeyVersions/1
auth-wrapper git clone git@github.com:connectedcars/private-module.git
```

Git clone with local key:

``` bash
export SSH_KEY_PATH=build.pem
export SSH_KEY_PASSWORD=thepassword
auth-wrapper git clone git@github.com:connectedcars/private-module.git
```

### SSH Certs

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

## Options

### Arguments

* -principals : Principals to request

### Environment variables

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

## Google Cloud KMS key setup

Create keyring and key:

``` bash
# Create keyring
gcloud kms keyrings create --location global ssh-keys
# It needs to be be SHA512 as the ssh client seems to default to this hashing algorithm and KMS pairs key size and hashing algorithms for some reason.
gcloud kms keys create ssh-key --keyring ssh-keys --location global --default-algorithm rsa-sign-pkcs1-4096-sha512 --purpose asymmetric-signing
# Give cloud build access to use the key
gcloud kms keys add-iam-policy-binding ssh-key --keyring=ssh-keys --location=global --member user@company.com --role roles/cloudkms.signerVerifier
```

## Local key

Current the go ssh key implementation does not support the new OpenSSH format so you need to use a PEM formated key:

``` bash
ssh-keygen -f build.key
ssh-keygen -f build.key -m 'PEM' -e > build.pem
```
