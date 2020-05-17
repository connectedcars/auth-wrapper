package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/connectedcars/auth-wrapper/kms/google"
	"github.com/connectedcars/auth-wrapper/server"
	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// Config contains the auth wrapper configuration
type Config struct {
	Command                 string
	Args                    []string
	RequestedPrincipals     []string
	SSHKeyPath              string
	SSHKeyPassword          string
	SSHSigningServerURL     string
	SSHCaKeyPath            string
	SSHCaKeyPassword        string
	SSHCaAuthorizedKeysPath string
	SSHSigningServerAddress string
	SSHAgentSocket          string
}

var principalsFlag = flag.String("principals", "", "requested principals")

func parseEnvironment() (*Config, error) {
	flag.Parse()

	config := &Config{
		Command:                 os.Getenv("WRAP_COMMAND"),
		Args:                    os.Args[1:],
		RequestedPrincipals:     strings.Split(os.Getenv("PRINCIPALS"), ","),
		SSHKeyPath:              os.Getenv("SSH_KEY_PATH"),
		SSHKeyPassword:          os.Getenv("SSH_KEY_PASSWORD"),
		SSHSigningServerURL:     os.Getenv("SSH_SIGNING_SERVER_URL"),
		SSHCaKeyPath:            os.Getenv("SSH_CA_KEY_PATH"),
		SSHCaKeyPassword:        os.Getenv("SSH_CA_KEY_PASSWORD"),
		SSHCaAuthorizedKeysPath: os.Getenv("SSH_CA_AUTHORIZED_KEYS_PATH"),
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

	if *principalsFlag != "" {
		config.RequestedPrincipals = strings.Split(*principalsFlag, ",")
	}

	if config.Command == "" {
		processName := filepath.Base(os.Args[0])
		if processName != "auth-wrapper" && processName != "__debug_bin" {
			// Get executable path
			ex, err := os.Executable()
			if err != nil {
				panic(err)
			}
			processPath := filepath.Dir(ex)

			// Remove wrapper location path
			currentPath := os.Getenv("PATH")
			cleanedPath := strings.Replace(currentPath, processPath+"/:", "", 1)
			cleanedPath = strings.Replace(cleanedPath, processPath+":", "", 1)
			os.Setenv("PATH", cleanedPath)

			config.Command = processName
		} else {
			if len(os.Args) < 2 {
				return nil, fmt.Errorf("auth-wrapper cmd args")
			}
			config.Command = os.Args[1]
			config.Args = os.Args[2:]
		}
	}

	// TODO: Do more config error validation

	if config.SSHSigningServerURL != "" && len(config.RequestedPrincipals) == 0 {
		return nil, fmt.Errorf("When SSH_SIGNING_SERVER_URL is set a list of principals needs to be provided")
	}

	return config, nil
}

func setupKeyring(config *Config) (agent.ExtendedAgent, error) {
	var signers []sshagent.SSHAlgorithmSigner
	var certificates []sshagent.SSHCertificate

	if config.SSHKeyPath != "" {
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
				Comment: config.SSHKeyPath,
			})
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
				Comment: config.SSHKeyPath,
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
				Comment: "agent key " + key.Comment,
			})
		}
	}

	if config.SSHSigningServerURL != "" {
		// TODO: Do something with the errors
		var errors []error
		for _, signer := range signers {
			userCert, err := fetchUserCert(config.SSHSigningServerURL, signer.Signer, config.Command, config.Args, config.RequestedPrincipals)
			if err != nil {
				errors = append(errors, err)
				continue
			}
			certificates = append(certificates, sshagent.SSHCertificate{
				Certificate: userCert,
				Comment:     "key " + config.SSHKeyPath,
			})
		}
	}

	return sshagent.NewSSHAlgorithmSignerKeyring(signers, certificates)
}

func fetchUserCert(signingServerURL string, signer ssh.AlgorithmSigner, command string, args []string, principals []string) (*ssh.Certificate, error) {
	// GET /certificate/challenge # { value: "{ \"timestamp\": \"2020-01-01T10:00:00.000Z\" \"random\": \"...\"}", signature: "signed by CA key" }
	var challenge server.Challenge
	err := httpJSONRequest("GET", signingServerURL+"/certificate/challenge", nil, &challenge)
	if err != nil {
		return nil, err
	}

	// POST /certificate # { challenge: "\...value", command: "", args: "", pubkey: "..." signature: "signed by user key" }
	certRequest := &server.CertificateRequest{
		Challenge:  &challenge,
		Command:    command,
		Args:       args,
		Principals: principals,
		PublicKey:  strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(signer.PublicKey())), "\n"),
	}

	// sign(challenge + command + args)
	certRequest.SignRequest(rand.Reader, signer)

	// get back { certificate: "base64 encoded cert" }
	var certResponse server.CertificateResponse
	err = httpJSONRequest("POST", signingServerURL+"/certificate", certRequest, &certResponse)
	if err != nil {
		return nil, err
	}
	userCertPubkey, _, _, _, err := ssh.ParseAuthorizedKey([]byte(certResponse.Certificate))
	if err != nil {
		return nil, nil
	}
	userCert := userCertPubkey.(*ssh.Certificate)
	return userCert, nil
}
