# Usage Examples


## Auth For Gcloud
`gcloud auth application-default login && gcloud auth login`


## auth-wrapper
```
auth-wrapper ssh support@192.168.7.1
auth-wrapper ssh support@192.168.7.1 'echo hello'
auth-wrapper ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR support@192.168.7.1 'sh -c "echo \"message\" > /tmp/random-place.txt"'
```
