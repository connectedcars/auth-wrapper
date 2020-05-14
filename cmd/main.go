package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/connectedcars/auth-wrapper/kms/google"
	"github.com/connectedcars/auth-wrapper/server"
	"github.com/connectedcars/auth-wrapper/sshagent"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

// authwrapper ssh 1.2.3.4
// Please write reason for login:
//

func main() {
	processName := filepath.Base(os.Args[0])
	var command string
	var args []string
	wrapCommand := os.Getenv("WRAP_COMMAND")
	if wrapCommand != "" {
		command = wrapCommand
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

	sshCaKeyPath := os.Getenv("SSH_CA_KEY_PATH")
	sshCaKeyPassword := os.Getenv("SSH_CA_KEY_PASSWORD")
	sshSigningServerAddress := os.Getenv("SSH_SIGNING_SERVER_LISTEN_ADDRESS")
	os.Unsetenv("SSH_CA_KEY_PATH")
	os.Unsetenv("SSH_CA_KEY_PASSWORD")
	os.Unsetenv("SSH_SIGNING_SERVER_LISTEN_ADDRESS")
	if sshCaKeyPath != "" && sshSigningServerAddress != "" {
		caPublickey, err := createSigningServer(sshCaKeyPath, sshCaKeyPassword, sshSigningServerAddress)
		if err != nil {
			log.Fatalf("createSigningServer: %v", err)
		}
		fmt.Fprintf(os.Stderr, "%s %s\n", strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(caPublickey)), "\n"), "ca "+sshCaKeyPath)
	}

	// Run command with SSH Agent
	sshKeyPath := os.Getenv("SSH_KEY_PATH")
	sshKeyPassword := os.Getenv("SSH_KEY_PASSWORD")
	sshSigningServerURL := os.Getenv("SSH_SIGNING_SERVER_URL")
	os.Unsetenv("SSH_KEY_PATH")
	os.Unsetenv("SSH_KEY_PASSWORD")
	var exitCode int
	var err error
	if sshKeyPath != "" {
		exitCode, err = runCommandWithSSHAgent(&SSHAgentConfig{
			userPrivateKeyPath:     sshKeyPath,
			userPrivateKeyPassword: sshKeyPassword,
			sshSigningServerURL:    sshSigningServerURL,
		}, command, args)

	} else {
		exitCode, err = runCommand(command, args)
	}
	if err != nil {
		log.Fatalf("runCommand: %v", err)
	}

	fmt.Fprintf(os.Stderr, "exit code: %v\n", exitCode)
	os.Exit(exitCode)
}

// SSHAgentConfig holds the config for the SSH Agent
type SSHAgentConfig struct {
	userPrivateKeyPath     string
	userPrivateKeyPassword string
	sshSigningServerURL    string
}

func runCommandWithSSHAgent(config *SSHAgentConfig, command string, args []string) (exitCode int, err error) {
	agent, err := createSSHAgent(config)
	if err != nil {
		return 255, fmt.Errorf("failed to setup ssh agent: %v", err)
	}

	sshAuthSock, err := sshagent.StartSSHAgentServer(agent)
	if err != nil {
		return 255, fmt.Errorf("Failed to start ssh agent server: %v", err)
	}
	fmt.Fprintf(os.Stderr, "Setting SSH_AUTH_SOCK using ssh key: %s\n", config.userPrivateKeyPath)
	os.Setenv("SSH_AUTH_SOCK", sshAuthSock)

	// Do string replacement for SSH_AUTH_SOCK
	for i, arg := range args {
		args[i] = strings.ReplaceAll(arg, "$SSH_AUTH_SOCK", sshAuthSock)
		args[i] = strings.ReplaceAll(args[i], "$$SSH_AUTH_SOCK", sshAuthSock)
	}

	// Print loaded keys
	keyList, err := agent.List()
	if err != nil {
		return 255, fmt.Errorf("Failed to list sshAgent keys %s: %v", config.userPrivateKeyPath, err)
	}
	fmt.Fprintf(os.Stderr, "Loaded keys:\n")
	for _, key := range keyList {
		fmt.Fprintf(os.Stderr, "%s %s\n", strings.TrimSuffix(string(ssh.MarshalAuthorizedKey(key)), "\n"), key.Comment)
	}

	return runCommand(command, args)
}

func createSSHAgent(config *SSHAgentConfig) (sshAgent agent.Agent, err error) {
	// TODO: Support mixing keys
	if strings.HasPrefix(config.userPrivateKeyPath, "kms://") {
		var err error
		userPrivateKeyPath := config.userPrivateKeyPath[6:]

		// Setup sshAgent
		sshAgent, err = google.NewKMSKeyring(userPrivateKeyPath, config.sshSigningServerURL)
		if err != nil {
			return nil, fmt.Errorf("Failed to setup KMS Keyring %s: %v", userPrivateKeyPath, err)
		}
	} else {
		// TODO: Create generic keyring that takes array of ssh.Signer's
		var privateKey interface{}
		privateKeyBytes, err := ioutil.ReadFile(config.userPrivateKeyPath)
		if err != nil {
			return nil, fmt.Errorf("Failed to read user SSH private key from %s: %v", config.userPrivateKeyPath, err)
		}
		privateKey, err = sshagent.ParsePrivateSSHKey(privateKeyBytes, config.userPrivateKeyPassword)
		if err != nil {
			return nil, fmt.Errorf("Failed to read or decrypt SSH private key from %s: %v", config.userPrivateKeyPath, err)
		}
		sshAgent = agent.NewKeyring()
		err = sshAgent.Add(agent.AddedKey{PrivateKey: privateKey, Comment: "my private key"})
		if err != nil {
			return nil, err
		}
	}
	return sshAgent, nil
}

func createSigningServer(caPrivateKeyPath string, sshCaKeyPassword string, address string) (ssh.PublicKey, error) {
	var caPublicKey ssh.PublicKey
	if strings.HasPrefix(caPrivateKeyPath, "kms://") {
		var err error
		kmsCaPrivateKeyPath := caPrivateKeyPath[6:]

		// Start the signing server
		caPrivateKey, err := google.NewKMSSigner(kmsCaPrivateKeyPath, false)
		if err != nil {
			return nil, fmt.Errorf("failed google.NewKMSSigner %v", err)
		}
		caSSHSigner, err := google.NewSSHSignerFromKMSSigner(caPrivateKey)
		if err != nil {
			return nil, fmt.Errorf("failed google.NewSignerFromSigner from: %v", err)
		}

		go func() {
			log.Fatal(server.StartHTTPSigningServer(caSSHSigner, address))
		}()
		caPublicKey = caPrivateKey.SSHPublicKey()

	} else {
		return nil, fmt.Errorf("Not implemented yet")
	}

	return caPublicKey, nil
}

func runCommand(command string, args []string) (exitCode int, err error) {
	cmd := exec.Command(command, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr

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
