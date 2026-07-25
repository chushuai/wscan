package rsync

import (
	"golang.org/x/crypto/ssh"
)

type SSH struct {
	client  *ssh.Client
	session *ssh.Session
}

func NewSSH(address string, _ string, _ string, cmd string) (*SSH, error) {
	config := &ssh.ClientConfig{
		Config:            ssh.Config{},
		User:              "",
		Auth:              nil,
		HostKeyCallback:   nil,
		BannerCallback:    nil,
		ClientVersion:     "",
		HostKeyAlgorithms: nil,
		Timeout:           0,
	}
	client, err := ssh.Dial("tcp", address, config)
	if err != nil {
		return nil, err
	}

	session, err := client.NewSession()
	if err != nil {
		return nil, err
	}

	// Call remote rsync server
	if err := session.Run(cmd); err != nil {
		return nil, err
	}

	// Handshake over SSH

	return &SSH{
		client:  client,
		session: session,
	}, nil
}

func (s *SSH) Write(p []byte) (n int, err error) {
	return s.session.Stdout.Write(p)
}

func (s *SSH) Read(p []byte) (n int, err error) {
	return s.session.Stdin.Read(p)
}

func (s *SSH) Close() error {
	return s.client.Close()
}
