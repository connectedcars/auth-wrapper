package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"syscall"

	"github.com/connectedcars/auth-wrapper/ssh"
)

func main() {
	sshKeyPath := os.Getenv("SSH_KEY_PATH")
	sshKeyPassword := os.Getenv("SSH_KEY_PASSWORD")
	os.Unsetenv("SSH_KEY_PATH")
	os.Unsetenv("SSH_KEY_PASSWORD")

	// Setup exec command
	command := os.Args[1]
	args := os.Args[2:]

	exitCode := runWithSSHAgent(command, args, sshKeyPath, sshKeyPassword)
	os.Exit(exitCode)
}

func runWithSSHAgent(command string, args []string, sshKeyPath string, sshKeyPassword string) (exitCode int) {
	if sshKeyPath != "" {
		var privateKey interface{}
		if strings.HasPrefix(sshKeyPath, "kms://") {
			var err error
			kmsKeyPath := sshKeyPath[6:]
			privateKey, err = ssh.NewKMSSigner(kmsKeyPath)
			if err != nil {
				fmt.Printf("Failed to setup KMSSigner %s: %v\n", kmsKeyPath, err)
				return 1
			}
		} else {
			privateKeyBytes, err := ioutil.ReadFile(sshKeyPath)
			if err != nil {
				fmt.Printf("Failed to read SSHPrivateKey from %s: %v\n", sshKeyPath, err)
				return 1
			}
			privateKey, err = ssh.ParsePrivateSSHKey(privateKeyBytes, sshKeyPassword)
			if err != nil {
				fmt.Printf("Failed to read SSHPrivateKey from %s: %v\n", sshKeyPath, err)
				return 1
			}
		}

		sshAuthSock, err := ssh.SetupAgent(privateKey)
		if err != nil {
			fmt.Printf("Failed to start ssh agent server: %v\n", err)
			return 1
		}
		fmt.Printf("Setting SSH_AUTH_SOCK using ssh key: %s", sshKeyPath)
		os.Setenv("SSH_AUTH_SOCK", sshAuthSock)
	}

	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if len(os.Args) < 2 {
		fmt.Println("auth-wrapper cmd args")
		return 1
	}

	if err := cmd.Start(); err != nil {
		fmt.Printf("cmd.Start: %v\n", err)
		return 1
	}

	err := cmd.Wait()
	if err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				return status.ExitStatus()
			}
			fmt.Printf("Failed to get status code: %v\n", err)
			return 1
		}
		fmt.Printf("cmd.Wait: %v\n", err)
		return 1
	}
	return 0
}
