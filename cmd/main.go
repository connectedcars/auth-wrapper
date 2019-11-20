package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	sshKeyPath := os.Getenv("SSH_KEY_PATH")
	sshKeyPassword := os.Getenv("SSH_KEY_PASSWORD")
	os.Unsetenv("SSH_KEY_PATH")
	os.Unsetenv("SSH_KEY_PASSWORD")

	// Setup exec command
	command := os.Args[1]
	args := os.Args[2:]

	exitCode, err := runWithSSHAgent(command, args, sshKeyPath, sshKeyPassword)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	}
	os.Exit(exitCode)
}

func runWithSSHAgent(command string, args []string, sshKeyPath string, sshKeyPassword string) (exitCode int, err error) {
	var sshAgent agent.Agent
	if sshKeyPath != "" {
		if strings.HasPrefix(sshKeyPath, "kms://") {
			var err error
			kmsKeyPath := sshKeyPath[6:]
			sshAgent, err = sshagent.NewKMSKeyring(kmsKeyPath)
			if err != nil {
				return 1, fmt.Errorf("Failed to setup KMS Keyring %s: %v", kmsKeyPath, err)
			}
		} else {
			var privateKey interface{}
			privateKeyBytes, err := ioutil.ReadFile(sshKeyPath)
			if err != nil {
				return 1, fmt.Errorf("Failed to read SSHPrivateKey from %s: %v", sshKeyPath, err)
			}
			privateKey, err = sshagent.ParsePrivateSSHKey(privateKeyBytes, sshKeyPassword)
			if err != nil {
				return 1, fmt.Errorf("Failed to read SSHPrivateKey from %s: %v", sshKeyPath, err)
			}
			sshAgent = agent.NewKeyring()
			err = sshAgent.Add(agent.AddedKey{PrivateKey: privateKey, Comment: "my private key"})
			if err != nil {
				return 1, err
			}
		}

		sshAuthSock, err := sshagent.StartSSHAgentServer(sshAgent)
		if err != nil {
			return 1, fmt.Errorf("Failed to start ssh agent server: %v", err)
		}
		fmt.Fprintf(os.Stderr, "Setting SSH_AUTH_SOCK using ssh key: %s\n", sshKeyPath)
		os.Setenv("SSH_AUTH_SOCK", sshAuthSock)

		// Do string replacement for SSH_AUTH_SOCK
		for i, arg := range args {
			fmt.Fprintf(os.Stderr, "arg[%d]: %s\n", i, arg)
			args[i] = strings.ReplaceAll(arg, "$SSH_AUTH_SOCK", sshAuthSock)
			args[i] = strings.ReplaceAll(arg, "$$SSH_AUTH_SOCK", sshAuthSock)
		}

	}

	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if len(os.Args) < 2 {
		return 1, fmt.Errorf("auth-wrapper cmd args")
	}

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("cmd.Start: %v", err)
	}

	err = cmd.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus(), nil
			}
			return 1, fmt.Errorf("Failed to get status code: %v", err)
		}
		return 1, fmt.Errorf("cmd.Wait: %v", err)
	}
	return 0, nil
}
