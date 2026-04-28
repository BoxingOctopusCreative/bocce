package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"sigs.k8s.io/yaml"
)

const (
	sha512Magic       = "$6$"
	defaultRounds     = 5000
	minRounds         = 1000
	maxRounds         = 999999999
	cloudConfigSchema = "https://raw.githubusercontent.com/canonical/cloud-init/main/cloudinit/config/schemas/schema-cloud-config-v1.json"
	schemaEnvPath     = "BOCCE_SCHEMA_PATH"
)

var shaCryptB64 = []byte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")
var version = "dev"

type cliConfig struct {
	templatePath   string
	sshKeyPath     string
	caCertPath     string
	starshipPreset string
	userName       string
	ubuntuProToken string
	password       string
	salt           string
	rounds         int
	outputDir      string
	dockerEnabled  bool
	showVersion    bool
}

type templateData struct {
	PasswordHash   string
	SshKey         string
	CaCert         string
	UserName       string
	StarshipPreset string
	UbuntuProToken string
	DockerEnabled  bool
}

func main() {
	cfg := parseFlags()
	if cfg.showVersion {
		fmt.Println(version)
		return
	}
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() cliConfig {
	var cfg cliConfig
	toolName := filepath.Base(os.Args[0])
	flag.CommandLine.Usage = func() {
		out := flag.CommandLine.Output()
		fmt.Fprintf(out, "%s - Generate validated cloud-init user-data\n\n", toolName)
		fmt.Fprintf(out, "Usage:\n  %s [options]\n\n", toolName)
		fmt.Fprintln(out, "Required options:")
		fmt.Fprintln(out, "  -ca-cert-path string")
		fmt.Fprintln(out, "  -password string")
		fmt.Fprintln(out)
		fmt.Fprintln(out, "Options:")
		flag.PrintDefaults()
	}

	flag.StringVar(&cfg.templatePath, "template", "templates/user-data.yaml.tmpl", "Path to cloud-config template")
	flag.StringVar(&cfg.sshKeyPath, "ssh-key-path", "", "Path to SSH public key file")
	flag.StringVar(&cfg.caCertPath, "ca-cert-path", "", "Path to CA certificate file")
	flag.StringVar(&cfg.starshipPreset, "starship-preset", "nerd-font-symbols", "Starship preset name")
	flag.StringVar(&cfg.userName, "user-name", "do-user", "User name")
	flag.StringVar(&cfg.ubuntuProToken, "ubuntu-pro-token", "", "Ubuntu Pro token")
	flag.StringVar(&cfg.password, "password", "", "Plaintext password to hash for cloud-init")
	flag.StringVar(&cfg.salt, "salt", "", "Optional explicit salt for SHA-512-crypt")
	flag.IntVar(&cfg.rounds, "rounds", defaultRounds, "SHA-512-crypt rounds (1000-999999999)")
	flag.StringVar(&cfg.outputDir, "output-path", ".", "Output directory for rendered user-data.yaml")
	flag.StringVar(&cfg.outputDir, "outputPath", ".", "Output directory for rendered user-data.yaml")
	flag.BoolVar(&cfg.dockerEnabled, "docker-enabled", false, "Enable Docker")
	flag.BoolVar(&cfg.showVersion, "version", false, "Print tool version and exit")
	flag.Parse()

	return cfg
}

func run(cfg cliConfig) error {
	if cfg.caCertPath == "" {
		return errors.New("missing required -ca-cert-path")
	}
	if cfg.password == "" {
		return errors.New("missing required -password")
	}
	if err := os.MkdirAll(cfg.outputDir, 0o755); err != nil {
		return fmt.Errorf("create output directory: %w", err)
	}

	tmplBytes, err := os.ReadFile(cfg.templatePath)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	caCertBytes, err := os.ReadFile(cfg.caCertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
	}
	sshPublicKey, err := resolveSSHPublicKey(cfg)
	if err != nil {
		return err
	}

	hash, err := mkpasswdSHA512Crypt(cfg.password, cfg.salt, cfg.rounds)
	if err != nil {
		return fmt.Errorf("derive password hash: %w", err)
	}

	normalized := normalizeTemplate(string(tmplBytes))
	tmpl, err := template.New("cloud-config").Option("missingkey=error").Parse(normalized)
	if err != nil {
		return fmt.Errorf("parse template: %w", err)
	}

	data := templateData{
		PasswordHash:   hash,
		SshKey:         sshPublicKey,
		CaCert:         indentMultiline(strings.TrimSpace(string(caCertBytes)), "      "),
		StarshipPreset: cfg.starshipPreset,
		UserName:       cfg.userName,
		UbuntuProToken: strings.TrimSpace(cfg.ubuntuProToken),
		DockerEnabled:  cfg.dockerEnabled,
	}

	validator, err := newCloudConfigValidator()
	if err != nil {
		return fmt.Errorf("initialize cloud-config schema validator: %w", err)
	}
	templateValidationData := templateData{
		PasswordHash:   "$6$testsalt$placeholderhash",
		SshKey:         "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIBplaceholder generated-by-BOCCE",
		CaCert:         indentMultiline("-----BEGIN CERTIFICATE-----\nMIIBplaceholder\n-----END CERTIFICATE-----", "      "),
		UserName:       "do-user",
		StarshipPreset: "nerd-font-symbols",
		UbuntuProToken: "template-validation-token",
	}
	if err := validateTemplateSchema(tmpl, templateValidationData, validator); err != nil {
		return err
	}

	var output strings.Builder
	if err := tmpl.Execute(&output, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	if err := validator.validateYAML(output.String()); err != nil {
		return fmt.Errorf("generated cloud-config failed schema validation: %w", err)
	}

	outputPath := filepath.Join(cfg.outputDir, "user-data.yaml")
	if err := os.WriteFile(outputPath, []byte(output.String()), 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func resolveSSHPublicKey(cfg cliConfig) (string, error) {
	if cfg.sshKeyPath != "" {
		sshKeyBytes, err := os.ReadFile(cfg.sshKeyPath)
		if err != nil {
			return "", fmt.Errorf("read ssh key: %w", err)
		}
		return strings.TrimSpace(string(sshKeyBytes)), nil
	}
	return generateEd25519KeyPair(cfg.outputDir)
}

func generateEd25519KeyPair(outputDir string) (string, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", fmt.Errorf("generate ed25519 keypair: %w", err)
	}

	privDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("marshal private key: %w", err)
	}
	privPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privDER})
	privateKeyPath := filepath.Join(outputDir, "id_ed25519")
	if err := os.WriteFile(privateKeyPath, privPEM, 0o600); err != nil {
		return "", fmt.Errorf("write private key: %w", err)
	}

	publicKey := formatOpenSSHEd25519PublicKey(pub)
	publicKeyPath := filepath.Join(outputDir, "id_ed25519.pub")
	if err := os.WriteFile(publicKeyPath, []byte(publicKey+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("write public key: %w", err)
	}

	return publicKey, nil
}

func formatOpenSSHEd25519PublicKey(pub ed25519.PublicKey) string {
	algo := []byte("ssh-ed25519")
	var blob bytes.Buffer
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(algo)))
	_, _ = blob.Write(algo)
	_ = binary.Write(&blob, binary.BigEndian, uint32(len(pub)))
	_, _ = blob.Write(pub)
	return "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob.Bytes()) + " generated-by-BOCCE"
}

func normalizeTemplate(raw string) string {
	replacer := strings.NewReplacer(
		"{{ PasswordHash }}", "{{ .PasswordHash }}",
		"{{ SshKey }}", "{{ .SshKey }}",
		"{{ UserName }}", "{{ .UserName }}",
		"{{ CaCert }}", "{{ .CaCert }}",
		"{{ StarshipPreset }}", "{{ .StarshipPreset }}",
		"{{ UbuntuProToken }}", "{{ .UbuntuProToken }}",
		"{{ DockerEnabled }}", "{{ .DockerEnabled }}",
	)
	return replacer.Replace(raw)
}

func indentMultiline(value, indent string) string {
	return strings.ReplaceAll(value, "\n", "\n"+indent)
}

func mkpasswdSHA512Crypt(password, salt string, rounds int) (string, error) {
	cleanSalt, err := sanitizeSalt(salt)
	if err != nil {
		return "", err
	}
	if cleanSalt == "" {
		cleanSalt, err = randomSalt(16)
		if err != nil {
			return "", err
		}
	}

	if rounds < minRounds || rounds > maxRounds {
		return "", fmt.Errorf("rounds must be between %d and %d", minRounds, maxRounds)
	}

	passBytes := []byte(password)
	saltBytes := []byte(cleanSalt)

	alt := sha512.New()
	_, _ = alt.Write(passBytes)
	_, _ = alt.Write(saltBytes)
	_, _ = alt.Write(passBytes)
	altSum := alt.Sum(nil)

	mainCtx := sha512.New()
	_, _ = mainCtx.Write(passBytes)
	_, _ = mainCtx.Write([]byte(sha512Magic))
	_, _ = mainCtx.Write(saltBytes)

	for i := len(passBytes); i > 64; i -= 64 {
		_, _ = mainCtx.Write(altSum)
	}
	_, _ = mainCtx.Write(altSum[:len(passBytes)%64])

	for i := len(passBytes); i > 0; i >>= 1 {
		if i&1 == 1 {
			_, _ = mainCtx.Write(altSum)
		} else {
			_, _ = mainCtx.Write(passBytes)
		}
	}
	final := mainCtx.Sum(nil)

	dp := sha512.New()
	for range len(passBytes) {
		_, _ = dp.Write(passBytes)
	}
	dpSum := dp.Sum(nil)
	pSeq := make([]byte, len(passBytes))
	for i := 0; i < len(passBytes); i += len(dpSum) {
		copy(pSeq[i:], dpSum)
	}

	ds := sha512.New()
	for i := 0; i < 16+int(final[0]); i++ {
		_, _ = ds.Write(saltBytes)
	}
	dsSum := ds.Sum(nil)
	sSeq := make([]byte, len(saltBytes))
	for i := 0; i < len(saltBytes); i += len(dsSum) {
		copy(sSeq[i:], dsSum)
	}

	for i := range rounds {
		roundCtx := sha512.New()
		if i%2 == 1 {
			_, _ = roundCtx.Write(pSeq)
		} else {
			_, _ = roundCtx.Write(final)
		}
		if i%3 != 0 {
			_, _ = roundCtx.Write(sSeq)
		}
		if i%7 != 0 {
			_, _ = roundCtx.Write(pSeq)
		}
		if i%2 == 1 {
			_, _ = roundCtx.Write(final)
		} else {
			_, _ = roundCtx.Write(pSeq)
		}
		final = roundCtx.Sum(nil)
	}

	hash := encodeSHA512Crypt(final)
	roundsPart := ""
	if rounds != defaultRounds {
		roundsPart = fmt.Sprintf("rounds=%d$", rounds)
	}
	return fmt.Sprintf("%s%s%s$%s", sha512Magic, roundsPart, cleanSalt, hash), nil
}

func sanitizeSalt(s string) (string, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, sha512Magic)
	if idx := strings.IndexByte(s, '$'); idx != -1 {
		s = s[:idx]
	}
	if len(s) > 16 {
		s = s[:16]
	}
	alphabet := string(shaCryptB64)
	for _, r := range s {
		if !strings.ContainsRune(alphabet, r) {
			return "", fmt.Errorf("salt contains invalid character %q", r)
		}
	}
	return s, nil
}

func randomSalt(length int) (string, error) {
	var out strings.Builder
	out.Grow(length)
	randomBytes := make([]byte, length)
	if _, err := rand.Read(randomBytes); err != nil {
		return "", fmt.Errorf("generate random salt: %w", err)
	}
	for _, b := range randomBytes {
		out.WriteByte(shaCryptB64[int(b)%len(shaCryptB64)])
	}
	return out.String(), nil
}

func encodeSHA512Crypt(final []byte) string {
	var out strings.Builder

	b64From24Bit(&out, final[0], final[21], final[42], 4)
	b64From24Bit(&out, final[22], final[43], final[1], 4)
	b64From24Bit(&out, final[44], final[2], final[23], 4)
	b64From24Bit(&out, final[3], final[24], final[45], 4)
	b64From24Bit(&out, final[25], final[46], final[4], 4)
	b64From24Bit(&out, final[47], final[5], final[26], 4)
	b64From24Bit(&out, final[6], final[27], final[48], 4)
	b64From24Bit(&out, final[28], final[49], final[7], 4)
	b64From24Bit(&out, final[50], final[8], final[29], 4)
	b64From24Bit(&out, final[9], final[30], final[51], 4)
	b64From24Bit(&out, final[31], final[52], final[10], 4)
	b64From24Bit(&out, final[53], final[11], final[32], 4)
	b64From24Bit(&out, final[12], final[33], final[54], 4)
	b64From24Bit(&out, final[34], final[55], final[13], 4)
	b64From24Bit(&out, final[56], final[14], final[35], 4)
	b64From24Bit(&out, final[15], final[36], final[57], 4)
	b64From24Bit(&out, final[37], final[58], final[16], 4)
	b64From24Bit(&out, final[59], final[17], final[38], 4)
	b64From24Bit(&out, final[18], final[39], final[60], 4)
	b64From24Bit(&out, final[40], final[61], final[19], 4)
	b64From24Bit(&out, final[62], final[20], final[41], 4)
	b64From24Bit(&out, 0, 0, final[63], 2)

	return out.String()
}

func b64From24Bit(out *strings.Builder, b2, b1, b0 byte, n int) {
	w := uint32(b2)<<16 | uint32(b1)<<8 | uint32(b0)
	for range n {
		out.WriteByte(shaCryptB64[w&0x3f])
		w >>= 6
	}
}

type cloudConfigValidator struct {
	schema *jsonschema.Schema
}

func newCloudConfigValidator() (*cloudConfigValidator, error) {
	schemaBytes, err := loadCloudConfigSchema()
	if err != nil {
		return nil, err
	}

	compiler := jsonschema.NewCompiler()
	if err := compiler.AddResource("schema.json", strings.NewReader(string(schemaBytes))); err != nil {
		return nil, fmt.Errorf("register schema resource: %w", err)
	}
	schema, err := compiler.Compile("schema.json")
	if err != nil {
		return nil, fmt.Errorf("compile schema: %w", err)
	}
	return &cloudConfigValidator{schema: schema}, nil
}

func loadCloudConfigSchema() ([]byte, error) {
	if path := strings.TrimSpace(os.Getenv(schemaEnvPath)); path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read schema from %s: %w", path, err)
		}
		return data, nil
	}

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Get(cloudConfigSchema)
	if err != nil {
		return nil, fmt.Errorf("download schema: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("download schema returned status %s", resp.Status)
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("read schema response: %w", err)
	}
	return data, nil
}

func validateTemplateSchema(tmpl *template.Template, data templateData, validator *cloudConfigValidator) error {
	var rendered strings.Builder
	if err := tmpl.Execute(&rendered, data); err != nil {
		return fmt.Errorf("render template for validation: %w", err)
	}
	if err := validator.validateYAML(rendered.String()); err != nil {
		return fmt.Errorf("template failed schema validation: %w", err)
	}
	return nil
}

func (v *cloudConfigValidator) validateYAML(content string) error {
	jsonBytes, err := yaml.YAMLToJSON([]byte(content))
	if err != nil {
		return fmt.Errorf("convert YAML to JSON: %w", err)
	}

	var payload any
	if err := json.Unmarshal(jsonBytes, &payload); err != nil {
		return fmt.Errorf("decode JSON payload: %w", err)
	}
	if err := v.schema.Validate(payload); err != nil {
		return err
	}
	return nil
}
