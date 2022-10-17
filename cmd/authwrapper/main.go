package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"os"
	"strings"
	"time"

	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
)

func main() {
	config, err := parseEnvironment()
	if err != nil {
		log.Fatalf(": %v", err)
	}

	if config.SSHCaKeyPath != "" && config.SSHCaAuthorizedKeysPath != "" && config.SSHSigningServerAddress != "" {
		var lifetime time.Duration = time.Hour * 1
		if config.SSHSigningLifetime != "" {
			lifetime, err = time.ParseDuration(config.SSHSigningLifetime)
			if err != nil {
				log.Fatalf(": %v", err)
			}
		}

		caPublickey, err := startSigningServer(
			config.SSHCaKeyPath,
			config.SSHCaKeyPassword,
			config.SSHCaAuthorizedKeysPath,
			config.SSHSigningServerAddress,
			lifetime,
		)
		if err != nil {
			log.Fatalf("createSigningServer: %v", err)
		}
		pubkeyString := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(caPublickey)), "\n")
		fmt.Fprintf(os.Stderr, "Starting signing server on %s with key:", config.SSHSigningServerAddress)
		fmt.Fprintf(os.Stderr, "%s %s\n", pubkeyString, "ca "+config.SSHCaKeyPath)
		if config.Command == "" {
			// Wait until we get killed
			select {}
		}
	}

	if config.Command == "" {
		log.Fatalf("auth-wrapper cmd args")
	}

	agent, err := setupKeyring(config)
	if err != nil {
		log.Fatalf("Failed to setup keyring: %v", err)
	}

	// List loaded keys
	keyList, err := agent.List()
	if err != nil {
		log.Fatalf("Failed to list sshAgent keys: %v", err)
	}

	if config.AuthWrapperQuiet == false {
		fmt.Fprintf(os.Stderr, "Loaded keys:\n")

		for _, key := range keyList {
			fmt.Fprintf(os.Stderr, "%s %s\n", strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"), key.Comment)
		}
	}

	var sshAuthSock string
	if config.SSHAgentSocketPath != "" {
		sshAuthSock = config.SSHAgentSocketPath
	} else {
		// Generate random filename
		dir, err := ioutil.TempDir(os.TempDir(), "")
		if err != nil {
			log.Fatal(err)
		}
		sshAuthSock = dir + "/" + generateRandomString(8) + ".sock"
	}

	sshagent.StartSSHAgentServer(agent, sshAuthSock)

	exitCode, err := runCommandWithSSHAgent(sshAuthSock, config.Command, config.Args)
	if err != nil {
		log.Fatalf("runCommandWithSSHAgent: %v", err)
	}

	if config.AuthWrapperQuiet == false {
		fmt.Fprintf(os.Stderr, "exit code: %v\n", exitCode)
	}
	os.Exit(exitCode)
}

const letterBytes = "abcdefghijklmnopqrstuvwxyz"

func generateRandomString(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = letterBytes[rand.Intn(len(letterBytes))]
	}
	return string(b)
}
