package tests

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func testSchemaPath(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	schemaPath := filepath.Join(tmp, "schema.json")
	// Minimal valid JSON schema to avoid external network dependency in tests.
	schema := `{"$schema":"https://json-schema.org/draft/2020-12/schema","type":"object"}`
	if err := os.WriteFile(schemaPath, []byte(schema), 0o644); err != nil {
		t.Fatalf("write test schema: %v", err)
	}
	return schemaPath
}

func TestCLIWritesUserDataToOutputPath(t *testing.T) {
	tmp := t.TempDir()
	sshPath := filepath.Join(tmp, "id.pub")
	caPath := filepath.Join(tmp, "ca.crt")
	outDir := filepath.Join(tmp, "out")

	if err := os.WriteFile(sshPath, []byte("ssh-ed25519 AAAATEST test@local\n"), 0o644); err != nil {
		t.Fatalf("write ssh key: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("LINE1\nLINE2\n"), 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"-ssh-key-path", sshPath,
		"-ca-cert-path", caPath,
		"-starship-preset", "nerd-font-symbols",
		"-password", "test123",
		"-salt", "saltsalt",
		"-outputPath", outDir,
	)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "BOCCE_SCHEMA_PATH="+testSchemaPath(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, string(output))
	}

	renderedPath := filepath.Join(outDir, "user-data.yaml")
	rendered, err := os.ReadFile(renderedPath)
	if err != nil {
		t.Fatalf("read rendered file: %v", err)
	}
	renderedStr := string(rendered)

	if !strings.Contains(renderedStr, "passwd: $6$saltsalt$g8hYET4opGR.gW2TdRR1kSWuMwaldiXgejIfsBfhEQ5TFSVcfaDPflWZ7KOFLCeYfVYP/jEl2JaDkr8MlraxB.") {
		t.Fatal("expected deterministic mkpasswd-compatible hash in output")
	}
	if !strings.Contains(renderedStr, "starship preset nerd-font-symbols") {
		t.Fatal("expected selected starship preset in output")
	}
	if strings.Contains(renderedStr, "ubuntu_pro:") {
		t.Fatal("did not expect ubuntu_pro section without token")
	}
}

func TestCLIRequiresPassword(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")

	if err := os.WriteFile(caPath, []byte("LINE1\nLINE2\n"), 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"-ca-cert-path", caPath,
	)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "BOCCE_SCHEMA_PATH="+testSchemaPath(t))
	output, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("expected go run to fail without password, output: %s", string(output))
	}
	if !strings.Contains(string(output), "missing required -password") {
		t.Fatalf("expected missing password error, got: %s", string(output))
	}
}

func TestCLIGeneratesSSHKeypairWhenMissingPath(t *testing.T) {
	tmp := t.TempDir()
	caPath := filepath.Join(tmp, "ca.crt")
	outDir := filepath.Join(tmp, "out")

	if err := os.WriteFile(caPath, []byte("LINE1\nLINE2\n"), 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"-ca-cert-path", caPath,
		"-starship-preset", "nerd-font-symbols",
		"-password", "test123",
		"-salt", "saltsalt",
		"-outputPath", outDir,
	)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "BOCCE_SCHEMA_PATH="+testSchemaPath(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, string(output))
	}

	if _, err := os.Stat(filepath.Join(outDir, "id_ed25519")); err != nil {
		t.Fatalf("expected generated private key file: %v", err)
	}
	pubPath := filepath.Join(outDir, "id_ed25519.pub")
	pubBytes, err := os.ReadFile(pubPath)
	if err != nil {
		t.Fatalf("read generated public key: %v", err)
	}
	pubKey := strings.TrimSpace(string(pubBytes))
	if !strings.HasPrefix(pubKey, "ssh-ed25519 ") {
		t.Fatalf("expected generated ssh-ed25519 public key, got: %q", pubKey)
	}

	rendered, err := os.ReadFile(filepath.Join(outDir, "user-data.yaml"))
	if err != nil {
		t.Fatalf("read rendered file: %v", err)
	}
	if !strings.Contains(string(rendered), pubKey) {
		t.Fatal("expected rendered output to include generated public key")
	}
}

func TestCLIIncludesUbuntuProSectionWhenTokenProvided(t *testing.T) {
	tmp := t.TempDir()
	sshPath := filepath.Join(tmp, "id.pub")
	caPath := filepath.Join(tmp, "ca.crt")
	outDir := filepath.Join(tmp, "out")

	if err := os.WriteFile(sshPath, []byte("ssh-ed25519 AAAATEST test@local\n"), 0o644); err != nil {
		t.Fatalf("write ssh key: %v", err)
	}
	if err := os.WriteFile(caPath, []byte("LINE1\nLINE2\n"), 0o644); err != nil {
		t.Fatalf("write ca cert: %v", err)
	}

	cmd := exec.Command(
		"go", "run", ".",
		"-ssh-key-path", sshPath,
		"-ca-cert-path", caPath,
		"-password", "test123",
		"-salt", "saltsalt",
		"-outputPath", outDir,
		"-ubuntu-pro-token", "token-123",
	)
	cmd.Dir = ".."
	cmd.Env = append(os.Environ(), "BOCCE_SCHEMA_PATH="+testSchemaPath(t))
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("go run failed: %v\n%s", err, string(output))
	}

	rendered, err := os.ReadFile(filepath.Join(outDir, "user-data.yaml"))
	if err != nil {
		t.Fatalf("read rendered file: %v", err)
	}
	renderedStr := string(rendered)
	if !strings.Contains(renderedStr, "ubuntu_pro:") {
		t.Fatal("expected ubuntu_pro section when token is provided")
	}
	if !strings.Contains(renderedStr, "token: token-123") {
		t.Fatal("expected ubuntu_pro token in rendered output")
	}
}
