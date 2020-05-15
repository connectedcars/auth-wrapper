package main

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/ssh"
)

func main() {
	processName := filepath.Base(os.Args[0])

	config, err := parseEnvironment()
	if err != nil {
		log.Fatalf(": %v", err)
	}

	var command string
	var args []string
	if config.WrapCommand != "" {
		command = config.WrapCommand
		args = os.Args[1:]
	} else if processName != "auth-wrapper" && processName != "__debug_bin" {
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

		command = processName
		args = os.Args[1:]
	} else {
		if len(os.Args) < 2 {
			fmt.Fprintf(os.Stderr, "auth-wrapper cmd args")
			os.Exit(1)
		}
		// Setup exec command
		command = os.Args[1]
		args = os.Args[2:]
	}

	if config.SSHCaKeyPath != "" && config.SSHSigningServerAddress != "" {
		caPublickey, err := startSigningServer(
			config.SSHCaKeyPath,
			config.SSHCaKeyPassword,
			config.SSHSigningServerAddress,
		)
		if err != nil {
			log.Fatalf("createSigningServer: %v", err)
		}
		pubkeyString := strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(caPublickey)), "\n")
		fmt.Fprintf(os.Stderr, "%s %s\n", pubkeyString, "ca "+config.SSHCaKeyPath)
	}

	var exitCode int
	if config.SSHKeyPath != "" || config.SSHAgentSocket != "" {
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

		exitCode, err = runCommandWithSSHAgent(agent, command, args)
		if err != nil {
			log.Fatalf("runCommandWithSSHAgent: %v", err)
		}
	} else {
		exitCode, err = runCommand(command, args)
		if err != nil {
			log.Fatalf("runCommand: %v", err)
		}
	}

	fmt.Fprintf(os.Stderr, "exit code: %v\n", exitCode)
	os.Exit(exitCode)
}
