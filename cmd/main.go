package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"syscall"

	"github.com/connectedcars/auth-wrapper/ssh"
)

func main() {
	sshKeyPath := os.Getenv("SSH_KEY_PATH")
	sshKeyPassword := os.Getenv("SSH_KEY_PASSWORD")
	os.Unsetenv("SSH_KEY_PATH")
	os.Unsetenv("SSH_KEY_PASSWORD")

	if sshKeyPath != "" {
		privateKeyBytes, err := ioutil.ReadFile(sshKeyPath)
		if err != nil {
			fmt.Printf("Failed to read SSHPrivateKey from %s: %v\n", sshKeyPath, err)
			os.Exit(1)
		}
		sshAuthSock, err := ssh.SetupAgent(privateKeyBytes, sshKeyPassword)
		if err != nil {
			fmt.Printf("Failed to start ssh agent server: %v\n", err)
			os.Exit(1)
		}
		os.Setenv("SSH_AUTH_SOCK", sshAuthSock)
	}

	if len(os.Args) < 2 {
		fmt.Println("auth-wrapper cmd args")
		os.Exit(1)
	}

	// Setup exec command
	command := os.Args[1]
	args := os.Args[2:]
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

	if err := cmd.Start(); err != nil {
		fmt.Printf("cmd.Start: %v\n", err)
		os.Exit(1)
	}

	if err := cmd.Wait(); err != nil {
		if exiterr, ok := err.(*exec.ExitError); ok {
			if status, ok := exiterr.Sys().(syscall.WaitStatus); ok {
				os.Exit(status.ExitStatus())
			}
		} else {
			fmt.Printf("cmd.Wait: %v\n", err)
			os.Exit(1)
		}
	}
}
