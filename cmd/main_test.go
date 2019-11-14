package main

import (
	"testing"
)

func TestSshAgentWithKMSKey(t *testing.T) {
	exitCode, err := runWithSSHAgent("git", []string{"ls-remote", "git@github.com:connectedcars/private-module.git"}, "kms://projects/connectedcars-staging/locations/global/keyRings/cloudbuilder/cryptoKeys/ssh-key/cryptoKeyVersions/3", "")
	if err != nil {
		t.Errorf("Failed with exitCode %v and error %v", exitCode, err)
	}
	if exitCode != 0 {
		t.Errorf("Failed with exitCode %v", exitCode)
	}
}
