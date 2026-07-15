package creds

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"network-compiler/internal/diag"
)

const (
	EnvUser        = "NETC_SSH_USER"
	EnvPassword    = "NETC_SSH_PASSWORD"
	EnvKeyFile     = "NETC_SSH_KEY_FILE"
	EnvCredentials = "NETC_CREDENTIALS"
)

// Options controls credential resolution. CLI values override environment, which
// overrides the credentials file.
type Options struct {
	User            string
	PasswordEnv     string
	KeyFile         string
	CredentialsFile string
}

// SSH holds resolved SSH credentials. Password and KeyFile are sensitive and
// must not be logged.
type SSH struct {
	User     string
	Password string
	KeyFile  string
}

// Resolve loads SSH credentials using priority: CLI options > environment >
// credentials file.
func Resolve(opts Options) (SSH, error) {
	filePath, err := credentialsPath(opts.CredentialsFile)
	if err != nil {
		return SSH{}, err
	}
	fromFile, err := readFile(filePath)
	if err != nil {
		return SSH{}, err
	}

	out := fromFile
	if v := strings.TrimSpace(os.Getenv(EnvUser)); v != "" {
		out.User = v
	}
	if v := passwordFromEnv(opts.PasswordEnv); v != "" {
		out.Password = v
	}
	if v := strings.TrimSpace(os.Getenv(EnvKeyFile)); v != "" {
		out.KeyFile = v
	}
	if v := strings.TrimSpace(opts.User); v != "" {
		out.User = v
	}
	if v := strings.TrimSpace(opts.KeyFile); v != "" {
		out.KeyFile = v
	}
	return out, nil
}

// CredRef converts resolved credentials into a diag CredRef.
func (s SSH) CredRef() diag.CredRef {
	return diag.CredRef{
		Username: s.User,
		Secret:   s.Password,
		KeyFile:  s.KeyFile,
	}
}

func credentialsPath(override string) (string, error) {
	if path := strings.TrimSpace(override); path != "" {
		return path, nil
	}
	if path := strings.TrimSpace(os.Getenv(EnvCredentials)); path != "" {
		return path, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".netc", "credentials.yaml"), nil
}

func readFile(path string) (SSH, error) {
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return SSH{}, nil
		}
		return SSH{}, err
	}
	if err := validateFileMode(path, info); err != nil {
		return SSH{}, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return SSH{}, err
	}
	return parseCredentials(data)
}

func validateFileMode(path string, info os.FileInfo) error {
	if info.Mode()&os.ModeType != 0 {
		return fmt.Errorf("%s: credentials file must be a regular file", path)
	}
	if perm := info.Mode().Perm(); perm&0077 != 0 {
		return fmt.Errorf("%s: credentials file must be mode 0600 (got %04o)", path, perm)
	}
	return nil
}

func parseCredentials(data []byte) (SSH, error) {
	out := SSH{}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, ":")
		if !ok {
			return SSH{}, fmt.Errorf("line %d: expected key: value", lineNo)
		}
		key = strings.TrimSpace(key)
		value = unquote(strings.TrimSpace(value))
		switch key {
		case "user", "username":
			out.User = value
		case "password":
			out.Password = value
		case "key_file", "keyfile":
			out.KeyFile = value
		default:
			return SSH{}, fmt.Errorf("line %d: unknown key %q", lineNo, key)
		}
	}
	if err := scanner.Err(); err != nil {
		return SSH{}, err
	}
	return out, nil
}

func passwordFromEnv(override string) string {
	if name := strings.TrimSpace(override); name != "" {
		return strings.TrimSpace(os.Getenv(name))
	}
	return strings.TrimSpace(os.Getenv(EnvPassword))
}

func unquote(value string) string {
	value = strings.TrimSpace(value)
	value = strings.Trim(value, `"`)
	value = strings.Trim(value, `'`)
	return value
}
