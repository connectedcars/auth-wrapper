package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"log"

	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
)

// https://medium.com/tarkalabs/ssh-recipes-in-go-an-interlude-6fa88a03d458
// https://gitlab.openebs.ci/openebs/maya/blob/b5f23e9b2e0c3e9d9503a5c1ae9c15cf8e439db5/vendor/golang.org/x/crypto/ssh/agent/client_test.go
// https://github.com/cloudtools/ssh-cert-authority
// https://github.com/signmykeyio/signmykey

func signCert(key string) (int, error) {
	// Parse public key string
	userPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(key))
	if err != nil {
		log.Fatal(err)
	}

	cert := &ssh.Certificate{
		Key:             userPubkey,
		KeyId:           "test",
		CertType:        ssh.UserCert,
		ValidPrincipals: []string{"tlb"},
		ValidAfter:      0,
		ValidBefore:     ssh.CertTimeInfinity, // uint64(time.Now().Add(time.Minute * 60).Unix()),
		Permissions: ssh.Permissions{
			CriticalOptions: map[string]string{},
			Extensions:      map[string]string{},
		},
	}

	/*sshKeyPath := "/Users/f736trbe/.ssh/id_rsa"
	privateKeyBytes, err := ioutil.ReadFile(sshKeyPath)
	if err != nil {
		return 1, fmt.Errorf("Failed to read SSHPrivateKey from %s: %v", sshKeyPath, err)
	}
	caPrivateKey, err := sshagent.ParsePrivateSSHKey(privateKeyBytes, "")
	if err != nil {
		return 1, fmt.Errorf("Failed to read SSHPrivateKey from %s: %v", sshKeyPath, err)
	}
	sshSigner, err := ssh.NewSignerFromKey(caPrivateKey)
	if err != nil {
		return 1, fmt.Errorf("Failed to read SSHPrivateKey from %s: %v", sshKeyPath, err)
	}*/

	cryptoSigner, err := sshagent.NewKMSSigner("projects/connectedcars-staging/locations/global/keyRings/cloudbuilder/cryptoKeys/ssh-key/cryptoKeyVersions/3", true)
	if err != nil {
		return 1, fmt.Errorf("Failed to read NewKMSSigner from: %v", err)
	}
	sshSigner, err := sshagent.NewSSHSignerFromKMSSigner(cryptoSigner)
	if err != nil {
		return 1, fmt.Errorf("Failed NewSignerFromSigner from: %v", err)
	}

	err = cert.SignCert(rand.Reader, sshSigner)
	if err != nil {
		return 1, fmt.Errorf("Failed SignCert from %v", err)
	}
	ioutil.WriteFile("/Users/f736trbe/git/connectedcars/auth-wrapper/cert.pub", ssh.MarshalAuthorizedKey(cert), 0644)
	return 1, nil
}
