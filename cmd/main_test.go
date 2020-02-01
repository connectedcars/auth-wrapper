package main

import (
	"testing"
)

func TestSshAgentWithKMSKey(t *testing.T) {
	exitCode, err := runCommandWithSSHAgent(&SSHAgentConfig{
		userPrivateKeyPath: "kms://projects/connectedcars-staging/locations/global/keyRings/cloudbuilder/cryptoKeys/ssh-key/cryptoKeyVersions/3"
	}, "git", []string{"ls-remote", "git@github.com:connectedcars/private-module.git"})
	if err != nil {
		t.Errorf("Failed with exitCode %v and error %v", exitCode, err)
	}
	if exitCode != 0 {
		t.Errorf("Failed with exitCode %v", exitCode)
	}
}
