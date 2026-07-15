package creds

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveEnvOverridesFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.yaml")
	if err := os.WriteFile(path, []byte("user: fileuser\npassword: filepass\nkey_file: /file/key\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(EnvUser, "envuser")
	t.Setenv(EnvPassword, "envpass")
	t.Setenv(EnvKeyFile, "/env/key")

	got, err := Resolve(Options{CredentialsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "envuser" || got.Password != "envpass" || got.KeyFile != "/env/key" {
		t.Fatalf("got = %#v", got)
	}
}

func TestResolveCLIOverridesEnv(t *testing.T) {
	t.Setenv(EnvUser, "envuser")
	t.Setenv(EnvPassword, "envpass")
	t.Setenv(EnvKeyFile, "/env/key")

	got, err := Resolve(Options{
		User:    "cliuser",
		KeyFile: "/cli/key",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "cliuser" || got.Password != "envpass" || got.KeyFile != "/cli/key" {
		t.Fatalf("got = %#v", got)
	}
}

func TestResolvePasswordEnvOverride(t *testing.T) {
	t.Setenv("MY_PASSWORD", "from-custom-env")
	got, err := Resolve(Options{PasswordEnv: "MY_PASSWORD"})
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != "from-custom-env" {
		t.Fatalf("password = %q", got.Password)
	}
}

func TestResolveMissingFileOK(t *testing.T) {
	got, err := Resolve(Options{CredentialsFile: filepath.Join(t.TempDir(), "missing.yaml")})
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "" || got.Password != "" || got.KeyFile != "" {
		t.Fatalf("got = %#v", got)
	}
}

func TestResolveRejectsLoosePermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte("user: admin\npassword: secret\n"), 0644); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(Options{CredentialsFile: path})
	if err == nil || !strings.Contains(err.Error(), "0600") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsWorldWritable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte("user: admin\n"), 0660); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(Options{CredentialsFile: path})
	if err == nil {
		t.Fatal("expected permission error")
	}
}

func TestResolveAccepts0600File(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	content := "user: fileuser\npassword: filepass\nkey_file: /home/me/.ssh/id_rsa\n"
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := Resolve(Options{CredentialsFile: path})
	if err != nil {
		t.Fatal(err)
	}
	if got.User != "fileuser" || got.Password != "filepass" || got.KeyFile != "/home/me/.ssh/id_rsa" {
		t.Fatalf("got = %#v", got)
	}
}

func TestResolveRejectsUnknownYAMLKey(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.WriteFile(path, []byte("token: abc\n"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(Options{CredentialsFile: path})
	if err == nil || !strings.Contains(err.Error(), "unknown key") {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveRejectsNonRegularFile(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "credentials.yaml")
	if err := os.Mkdir(dir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err := Resolve(Options{CredentialsFile: dir})
	if err == nil || !strings.Contains(err.Error(), "regular file") {
		t.Fatalf("err = %v", err)
	}
}

func TestCredRefMapping(t *testing.T) {
	ref := (SSH{User: "admin", Password: "secret", KeyFile: "/k"}).CredRef()
	if ref.Username != "admin" || ref.Secret != "secret" || ref.KeyFile != "/k" {
		t.Fatalf("ref = %#v", ref)
	}
}

func TestCredentialsPathDefault(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	path, err := credentialsPath("")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(home, ".netc", "credentials.yaml")
	if path != want {
		t.Fatalf("path = %q want %q", path, want)
	}
}

func TestCredentialsPathNETCEnv(t *testing.T) {
	custom := filepath.Join(t.TempDir(), "custom.yaml")
	t.Setenv(EnvCredentials, custom)
	path, err := credentialsPath("")
	if err != nil {
		t.Fatal(err)
	}
	if path != custom {
		t.Fatalf("path = %q want %q", path, custom)
	}
}
