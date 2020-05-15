package main

import (
	"crypto/rand"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/connectedcars/auth-wrapper/kms/google"
	"github.com/connectedcars/auth-wrapper/server"
	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config contains the auth wrapper configuration
type Config struct {
	WrapCommand             string
	SSHKeyPath              string
	SSHKeyPassword          string
	SSHSigningServerURL     string
	SSHCaKeyPath            string
	SSHCaKeyPassword        string
	SSHSigningServerAddress string
	SSHAgentSocket          string
}

func parseEnvironment() (*Config, error) {
	config := &Config{
		WrapCommand:             os.Getenv("WRAP_COMMAND"),
		SSHKeyPath:              os.Getenv("SSH_KEY_PATH"),
		SSHKeyPassword:          os.Getenv("SSH_KEY_PASSWORD"),
		SSHSigningServerURL:     os.Getenv("SSH_SIGNING_SERVER_URL"),
		SSHCaKeyPath:            os.Getenv("SSH_CA_KEY_PATH"),
		SSHCaKeyPassword:        os.Getenv("SSH_CA_KEY_PASSWORD"),
		SSHSigningServerAddress: os.Getenv("SSH_SIGNING_SERVER_LISTEN_ADDRESS"),
		SSHAgentSocket:          os.Getenv("SSH_AUTH_SOCK"),
	}
	os.Unsetenv("WRAP_COMMAND")
	os.Unsetenv("SSH_KEY_PATH")
	os.Unsetenv("SSH_KEY_PASSWORD")
	os.Unsetenv("SSH_SIGNING_SERVER_URL")
	os.Unsetenv("SSH_CA_KEY_PATH")
	os.Unsetenv("SSH_CA_KEY_PASSWORD")
	os.Unsetenv("SSH_SIGNING_SERVER_LISTEN_ADDRESS")
	os.Unsetenv("SSH_AUTH_SOCK")

	// TODO: Do basic error validation

	return config, nil
}

func setupKeyring(config *Config) (agent.ExtendedAgent, error) {
	var signers []sshagent.SSHAlgorithmSigner
	var certificates []sshagent.SSHCertificate

	if config.SSHKeyPath != "" {
		var userSigner ssh.AlgorithmSigner
		if strings.HasPrefix(config.SSHKeyPath, "kms://") {
			var err error
			userPrivateKeyPath := config.SSHKeyPath[6:]
			userPrivateKey, err := google.NewKMSSigner(userPrivateKeyPath, false)
			if err != nil {
				return nil, err
			}
			signer, err := google.NewSSHSignerFromSigner(userPrivateKey, userPrivateKey.Digest())
			if err != nil {
				return nil, fmt.Errorf("failed NewSignerFromSigner from: %v", err)
			}
			signers = append(signers, sshagent.SSHAlgorithmSigner{
				Signer:  signer,
				Comment: "google kms key " + userPrivateKeyPath,
			})
			userSigner = signer
		} else {
			privateKeyBytes, err := ioutil.ReadFile(config.SSHKeyPath)
			if err != nil {
				return nil, fmt.Errorf("Failed to read user SSH private key from %s: %v", config.SSHKeyPath, err)
			}

			var privateKey interface{}
			privateKey, err = sshagent.ParsePrivateSSHKey(privateKeyBytes, config.SSHKeyPath)
			if err != nil {
				return nil, fmt.Errorf("Failed to read or decrypt SSH private key from %s: %v", config.SSHKeyPath, err)
			}
			signer, err := ssh.NewSignerFromKey(privateKey)

			algorithmSigner, ok := signer.(ssh.AlgorithmSigner)
			if !ok {
				return nil, fmt.Errorf("signature does not support non-default signature algorithm: %T", signer)
			}
			signers = append(signers, sshagent.SSHAlgorithmSigner{
				Signer:  algorithmSigner,
				Comment: "local key " + config.SSHKeyPath,
			})
			userSigner = algorithmSigner
		}

		if config.SSHSigningServerURL != "" {
			// GET /certificate/challenge # { value: "{ \"timestamp\": \"2020-01-01T10:00:00.000Z\" \"random\": \"...\"}", signature: "signed by CA key" }
			var challenge server.Challenge
			err := httpJSONRequest("GET", config.SSHSigningServerURL+"/certificate/challenge", nil, &challenge)
			if err != nil {
				return nil, err
			}

			// POST /certificate # { challenge: "\...value", command: "", args: "", pubkey: "..." signature: "signed by user key" }
			certRequest := &server.CertificateRequest{
				Challenge: &challenge,
				Command:   "some command", // TODO: Get command
				Args:      []string{},     // TODO: Get args
				PublicKey: string(ssh.MarshalAuthorizedKey(userSigner.PublicKey())),
			}
			// sign(challenge + command + args)
			certRequest.SignRequest(rand.Reader, userSigner)

			// get back { certificate: "base64 encoded cert" }
			var certResponse server.CertificateResponse
			err = httpJSONRequest("POST", config.SSHSigningServerURL+"/certificate", certRequest, &certResponse)
			if err != nil {
				return nil, err
			}
			userCertPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certResponse.Certificate))
			if err != nil {
				return nil, nil
			}
			userCert := userCertPubkey.(*ssh.Certificate)

			certificates = append(certificates, sshagent.SSHCertificate{
				Certificate: userCert,
				Comment:     "user key " + config.SSHKeyPath,
			})
		}

	}

	if config.SSHAgentSocket != "" {
		agent, err := sshagent.ConnectSSHAgent(config.SSHAgentSocket)
		if err != nil {
			return nil, err
		}

		keys, err := agent.List()
		if err != nil {
			return nil, err
		}

		for _, key := range keys {
			signer := sshagent.NewSSHAlgorithmSigner(agent, key)
			signers = append(signers, sshagent.SSHAlgorithmSigner{
				Signer:  signer,
				Comment: "agent key",
			})
		}
	}

	return sshagent.NewSSHAlgorithmSignerKeyring(&signers, &certificates)
}
