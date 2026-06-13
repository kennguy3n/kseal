package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the on-disk CLI configuration. It stores connection profiles only —
// endpoints, the tenant scope, and *references* to where an API key can be read
// from (an environment variable name or a file path). It NEVER stores an API
// key value itself, so the config file is safe to commit to a dotfiles repo or
// share across a team.
type Config struct {
	// CurrentProfile is the profile used when --profile is not supplied.
	CurrentProfile string `json:"current_profile"`
	// Profiles is the set of named connection profiles.
	Profiles map[string]*Profile `json:"profiles"`
}

// Profile is a named connection target.
type Profile struct {
	// Endpoint is the base URL of the kseal server (e.g. https://api.kseal.io).
	Endpoint string `json:"endpoint"`
	// Tenant is the default tenant id this profile is scoped to. Tenant-scoped
	// commands use it unless --tenant overrides it. Keeping it on the profile
	// makes self-service operators safe-by-default: they cannot accidentally
	// touch another tenant.
	Tenant string `json:"tenant,omitempty"`
	// APIKeyEnv is the name of the environment variable to read the API key
	// from. Defaults to KSEAL_API_KEY when empty. The key value is never stored.
	APIKeyEnv string `json:"api_key_env,omitempty"`
	// APIKeyFile is an optional path to a file containing the API key (used when
	// the env var is unset). The file is read at runtime and never echoed.
	APIKeyFile string `json:"api_key_file,omitempty"`
}

const (
	defaultAPIKeyEnv  = "KSEAL_API_KEY"
	defaultProfile    = "default"
	defaultEndpoint   = "http://localhost:8080"
	configEnvVar      = "KSEAL_CONFIG"
	xdgConfigHomeEnv  = "XDG_CONFIG_HOME"
	configDirName     = "kseal"
	configFileName    = "config.json"
	configFilePerm    = 0o600
	configDirPermBits = 0o700
)

// ErrProfileNotFound is returned when a named profile is missing.
var ErrProfileNotFound = errors.New("profile not found")

// DefaultConfigPath resolves the config file path, honoring KSEAL_CONFIG and
// XDG_CONFIG_HOME, falling back to ~/.config/kseal/config.json.
func DefaultConfigPath() (string, error) {
	if p := os.Getenv(configEnvVar); p != "" {
		return p, nil
	}
	base := os.Getenv(xdgConfigHomeEnv)
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("resolve home dir: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, configDirName, configFileName), nil
}

// LoadConfig reads the config file at path. A missing file yields an empty,
// usable config rather than an error, so first-run and CI use need no setup.
func LoadConfig(path string) (*Config, error) {
	cfg := &Config{Profiles: map[string]*Profile{}}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return cfg, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	if cfg.Profiles == nil {
		cfg.Profiles = map[string]*Profile{}
	}
	return cfg, nil
}

// Save writes the config atomically with 0600 permissions.
func (c *Config) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), configDirPermBits); err != nil {
		return fmt.Errorf("create config dir: %w", err)
	}
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		return fmt.Errorf("encode config: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return fmt.Errorf("create temp config: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(configFilePerm); err != nil {
		tmp.Close()
		return fmt.Errorf("chmod temp config: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return fmt.Errorf("write temp config: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp config: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		return fmt.Errorf("commit config: %w", err)
	}
	return nil
}

// ResolveProfile returns the named profile, falling back to CurrentProfile and
// then to a synthesized default profile so the CLI works with zero config.
func (c *Config) ResolveProfile(name string) (string, *Profile, error) {
	if name == "" {
		name = c.CurrentProfile
	}
	if name == "" {
		name = defaultProfile
	}
	if p, ok := c.Profiles[name]; ok {
		return name, p, nil
	}
	// A bare "default" with no stored config is always usable.
	if name == defaultProfile {
		return name, &Profile{Endpoint: defaultEndpoint}, nil
	}
	return name, nil, fmt.Errorf("%w: %q", ErrProfileNotFound, name)
}

// apiKeyEnvName returns the env var name the profile reads its key from.
func (p *Profile) apiKeyEnvName() string {
	if p.APIKeyEnv != "" {
		return p.APIKeyEnv
	}
	return defaultAPIKeyEnv
}

// resolveAPIKey returns the API key for the profile, reading it from the
// configured environment variable first and then from the configured file. It
// returns the key value to the caller but the value is never logged or printed.
func (p *Profile) resolveAPIKey() (string, error) {
	if v := strings.TrimSpace(os.Getenv(p.apiKeyEnvName())); v != "" {
		return v, nil
	}
	if p.APIKeyFile != "" {
		data, err := os.ReadFile(p.APIKeyFile)
		if err != nil {
			return "", fmt.Errorf("read api key file: %w", err)
		}
		if v := strings.TrimSpace(string(data)); v != "" {
			return v, nil
		}
	}
	return "", newAuthError("no API key found: set $%s or configure an api_key_file for this profile", p.apiKeyEnvName())
}
