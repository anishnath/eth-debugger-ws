package ssh

import (
	"fmt"
	"golang.org/x/crypto/ssh"
)

type SSHClient struct {
	conn *ssh.Client
}

func NewSSHClient(privateKey, username, host string) (*SSHClient, error) {
	signer, err := parsePrivateKey(privateKey)
	if err != nil {
		return nil, fmt.Errorf("Error parsing private key: %v", err)
	}

	config := createSSHConfig(signer, username)

	conn, err := connectToRemoteServer(config, host)
	if err != nil {
		return nil, fmt.Errorf("Error connecting to remote server: %v", err)
	}

	client := &SSHClient{
		conn: conn,
	}

	return client, nil
}

func (c *SSHClient) RunCommand(command string) ([]byte, error) {
	session, err := c.conn.NewSession()
	if err != nil {
		return nil, fmt.Errorf("Error creating session: %v", err)
	}
	defer session.Close()

	return session.CombinedOutput(command)
}

func (c *SSHClient) Close() error {
	return c.conn.Close()
}

func parsePrivateKey(privateKey string) (ssh.Signer, error) {
	return ssh.ParsePrivateKey([]byte(privateKey))
}

func createSSHConfig(signer ssh.Signer, username string) *ssh.ClientConfig {
	return &ssh.ClientConfig{
		User: username,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
	}
}

func connectToRemoteServer(config *ssh.ClientConfig, host string) (*ssh.Client, error) {
	return ssh.Dial("tcp", host, config)
}
