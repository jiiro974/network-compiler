package transport

import (
	"context"
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"

	"network-compiler/internal/diag"
)

func (s *SSHRunner) dial(ctx context.Context, target diag.Target) (*ssh.Client, error) {
	if s.Config.InsecureHostKey {
		return s.dialInsecure(ctx, target)
	}
	if s.Config.KnownHostsFile == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return nil, fmt.Errorf("known_hosts required: %w", err)
		}
		s.Config.KnownHostsFile = home + "/.ssh/known_hosts"
	}
	callback, err := knownhosts.New(s.Config.KnownHostsFile)
	if err != nil {
		return nil, fmt.Errorf("load known_hosts: %w", err)
	}
	config := &ssh.ClientConfig{
		User:            target.Creds.Username,
		Auth:            sshAuth(target.Creds),
		HostKeyCallback: callback,
		Timeout:         s.Config.ConnectTimeout,
	}
	if config.User == "" {
		config.User = "admin"
	}
	addr := net.JoinHostPort(target.Address, "22")
	dialer := &net.Dialer{Timeout: s.Config.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func (s *SSHRunner) dialInsecure(ctx context.Context, target diag.Target) (*ssh.Client, error) {
	config := &ssh.ClientConfig{
		User:            target.Creds.Username,
		Auth:            sshAuth(target.Creds),
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         s.Config.ConnectTimeout,
	}
	if config.User == "" {
		config.User = "admin"
	}
	addr := net.JoinHostPort(target.Address, "22")
	dialer := &net.Dialer{Timeout: s.Config.ConnectTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	c, chans, reqs, err := ssh.NewClientConn(conn, addr, config)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}
	return ssh.NewClient(c, chans, reqs), nil
}

func sshAuth(creds diag.CredRef) []ssh.AuthMethod {
	var methods []ssh.AuthMethod
	if creds.KeyFile != "" {
		key, err := os.ReadFile(creds.KeyFile)
		if err == nil {
			signer, err := ssh.ParsePrivateKey(key)
			if err == nil {
				methods = append(methods, ssh.PublicKeys(signer))
			}
		}
	}
	if creds.Secret != "" {
		methods = append(methods, ssh.Password(creds.Secret))
	}
	return methods
}
