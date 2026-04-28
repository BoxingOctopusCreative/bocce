package main

import (
	"crypto/rand"
	"crypto/sha512"
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
	"text/template"
)

const (
	sha512Magic   = "$6$"
	defaultRounds = 5000
	minRounds     = 1000
	maxRounds     = 999999999
)

var shaCryptB64 = []byte("./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz")

type cliConfig struct {
	templatePath   string
	sshKeyPath     string
	caCertPath     string
	starshipPreset string
	password       string
	salt           string
	rounds         int
	outputPath     string
}

type templateData struct {
	PasswordHash   string
	SshKey         string
	CaCert         string
	StarshipPreset string
}

func main() {
	cfg := parseFlags()
	if err := run(cfg); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func parseFlags() cliConfig {
	var cfg cliConfig

	flag.StringVar(&cfg.templatePath, "template", "user-data.yaml.tmpl", "Path to cloud-config template")
	flag.StringVar(&cfg.sshKeyPath, "ssh-key-path", "", "Path to SSH public key file")
	flag.StringVar(&cfg.caCertPath, "ca-cert-path", "", "Path to CA certificate file")
	flag.StringVar(&cfg.starshipPreset, "starship-preset", "nerd-font-symbols", "Starship preset name")
	flag.StringVar(&cfg.password, "password", "", "Plaintext password to hash for cloud-init")
	flag.StringVar(&cfg.salt, "salt", "", "Optional explicit salt for SHA-512-crypt")
	flag.IntVar(&cfg.rounds, "rounds", defaultRounds, "SHA-512-crypt rounds (1000-999999999)")
	flag.StringVar(&cfg.outputPath, "output", "", "Output path (default stdout)")
	flag.Parse()

	return cfg
}

func run(cfg cliConfig) error {
	if cfg.sshKeyPath == "" {
		return errors.New("missing required -ssh-key-path")
	}
	if cfg.caCertPath == "" {
		return errors.New("missing required -ca-cert-path")
	}
	if cfg.password == "" {
		return errors.New("missing required -password")
	}

	tmplBytes, err := os.ReadFile(cfg.templatePath)
	if err != nil {
		return fmt.Errorf("read template: %w", err)
	}
	sshKeyBytes, err := os.ReadFile(cfg.sshKeyPath)
	if err != nil {
		return fmt.Errorf("read ssh key: %w", err)
	}
	caCertBytes, err := os.ReadFile(cfg.caCertPath)
	if err != nil {
		return fmt.Errorf("read ca cert: %w", err)
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
		SshKey:         strings.TrimSpace(string(sshKeyBytes)),
		CaCert:         indentMultiline(strings.TrimSpace(string(caCertBytes)), "      "),
		StarshipPreset: cfg.starshipPreset,
	}

	var output strings.Builder
	if err := tmpl.Execute(&output, data); err != nil {
		return fmt.Errorf("execute template: %w", err)
	}

	if cfg.outputPath == "" {
		fmt.Print(output.String())
		return nil
	}
	if err := os.WriteFile(cfg.outputPath, []byte(output.String()), 0o644); err != nil {
		return fmt.Errorf("write output: %w", err)
	}
	return nil
}

func normalizeTemplate(raw string) string {
	replacer := strings.NewReplacer(
		"{{ PasswordHash }}", "{{ .PasswordHash }}",
		"{{ SshKey }}", "{{ .SshKey }}",
		"{{ CaCert }}", "{{ .CaCert }}",
		"{StarshipPreset}", "{{ .StarshipPreset }}",
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
	for i := 0; i < len(passBytes); i++ {
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

	for i := 0; i < rounds; i++ {
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
	for i := 0; i < n; i++ {
		out.WriteByte(shaCryptB64[w&0x3f])
		w >>= 6
	}
}
