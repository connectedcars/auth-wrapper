package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	config, err := parseEnvironment()
	if err != nil {
		log.Fatalf(": %v", err)
	}

	// TODO: Default to port if nothing has been set
	if config.SSHCaKeyPath != "" && config.SSHSigningServerAddress != "" {
		caPublickey, err := startSigningServer(
			config.SSHCaKeyPath,
			config.SSHCaKeyPassword,
			config.SSHCaAuthorizedKeysPath,
			config.SSHSigningServerAddress,
		)
		if err != nil {
			log.Fatalf("createSigningServer: %v", err)
		}
		pubkeyString := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(caPublickey)), "\n")
		fmt.Fprintf(os.Stderr, "Starting signing server on %s with key:", config.SSHSigningServerAddress)
		fmt.Fprintf(os.Stderr, "%s %s\n", pubkeyString, "ca "+config.SSHCaKeyPath)
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
	fmt.Fprintf(os.Stderr, "Loaded keys:\n")
	for _, key := range keyList {
		fmt.Fprintf(os.Stderr, "%s %s\n", strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"), key.Comment)
	}

	exitCode, err := runCommandWithSSHAgent(agent, config.Command, config.Args)
	if err != nil {
		log.Fatalf("runCommandWithSSHAgent: %v", err)
	}

	fmt.Fprintf(os.Stderr, "exit code: %v\n", exitCode)
	os.Exit(exitCode)
}
