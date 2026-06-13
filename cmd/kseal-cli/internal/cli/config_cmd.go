package cli

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"
)

// newConfigCmd manages local connection profiles. These commands never touch
// the server and never read or write API key values — only references to where
// a key is read from.
func newConfigCmd(c *CLI) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "config",
		Short: "Manage local connection profiles (endpoint, tenant, API-key source)",
	}
	cmd.AddCommand(
		newConfigSetCmd(c),
		newConfigUseCmd(c),
		newConfigListCmd(c),
		newConfigCurrentCmd(c),
		newConfigRemoveCmd(c),
	)
	return cmd
}

func newConfigSetCmd(c *CLI) *cobra.Command {
	var (
		name       string
		endpoint   string
		tenant     string
		apiKeyEnv  string
		apiKeyFile string
		makeCur    bool
	)
	cmd := &cobra.Command{
		Use:   "set-profile",
		Short: "Create or update a connection profile",
		Long: "Create or update a named connection profile. The API key value is never " +
			"stored; configure either --api-key-env (an environment variable name, default " +
			"KSEAL_API_KEY) or --api-key-file (a path read at runtime).",
		RunE: func(cmd *cobra.Command, _ []string) error {
			if name == "" {
				return newUsageError("--name is required")
			}
			p := c.cfg.Profiles[name]
			if p == nil {
				p = &Profile{}
			}
			if endpoint != "" {
				p.Endpoint = endpoint
			}
			if cmd.Flags().Changed("tenant-id") {
				p.Tenant = tenant
			}
			if cmd.Flags().Changed("api-key-env") {
				p.APIKeyEnv = apiKeyEnv
			}
			if cmd.Flags().Changed("api-key-file") {
				p.APIKeyFile = apiKeyFile
			}
			if p.Endpoint == "" {
				p.Endpoint = defaultEndpoint
			}
			c.cfg.Profiles[name] = p
			if makeCur || c.cfg.CurrentProfile == "" {
				c.cfg.CurrentProfile = name
			}
			if err := c.cfg.Save(c.configPathResolved); err != nil {
				return err
			}
			return c.emitProfile(name, p)
		},
	}
	f := cmd.Flags()
	f.StringVar(&name, "name", "", "profile name")
	f.StringVar(&endpoint, "endpoint", "", "server base URL")
	f.StringVar(&tenant, "tenant-id", "", "default tenant id for this profile")
	f.StringVar(&apiKeyEnv, "api-key-env", "", "environment variable to read the API key from (default KSEAL_API_KEY)")
	f.StringVar(&apiKeyFile, "api-key-file", "", "file to read the API key from when the env var is unset")
	f.BoolVar(&makeCur, "use", false, "also set this as the current profile")
	return cmd
}

func newConfigUseCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "use <profile>",
		Short: "Set the current profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if _, ok := c.cfg.Profiles[name]; !ok {
				return newUsageError("%w: %q", ErrProfileNotFound, name)
			}
			c.cfg.CurrentProfile = name
			if err := c.cfg.Save(c.configPathResolved); err != nil {
				return err
			}
			fmt.Fprintf(c.out, "current profile: %s\n", name)
			return nil
		},
	}
}

func newConfigCurrentCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the current profile",
		RunE: func(_ *cobra.Command, _ []string) error {
			name, p, err := c.cfg.ResolveProfile("")
			if err != nil {
				return err
			}
			return c.emitProfile(name, p)
		},
	}
}

func newConfigListCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List configured profiles",
		RunE: func(_ *cobra.Command, _ []string) error {
			names := make([]string, 0, len(c.cfg.Profiles))
			for n := range c.cfg.Profiles {
				names = append(names, n)
			}
			sort.Strings(names)
			type row struct {
				Name      string `json:"name"`
				Current   bool   `json:"current"`
				Endpoint  string `json:"endpoint"`
				Tenant    string `json:"tenant,omitempty"`
				APIKeyEnv string `json:"api_key_env"`
			}
			out := make([]row, 0, len(names))
			tbl := table{Headers: []string{"CURRENT", "NAME", "ENDPOINT", "TENANT", "API_KEY_ENV"}}
			for _, n := range names {
				p := c.cfg.Profiles[n]
				cur := ""
				if n == c.cfg.CurrentProfile {
					cur = "*"
				}
				out = append(out, row{Name: n, Current: n == c.cfg.CurrentProfile, Endpoint: p.Endpoint, Tenant: p.Tenant, APIKeyEnv: p.apiKeyEnvName()})
				tbl.Rows = append(tbl.Rows, []string{cur, n, p.Endpoint, p.Tenant, p.apiKeyEnvName()})
			}
			return c.emit(out, tbl)
		},
	}
}

func newConfigRemoveCmd(c *CLI) *cobra.Command {
	return &cobra.Command{
		Use:   "remove <profile>",
		Short: "Remove a profile",
		Args:  cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			name := args[0]
			if _, ok := c.cfg.Profiles[name]; !ok {
				return newUsageError("%w: %q", ErrProfileNotFound, name)
			}
			delete(c.cfg.Profiles, name)
			if c.cfg.CurrentProfile == name {
				c.cfg.CurrentProfile = ""
			}
			if err := c.cfg.Save(c.configPathResolved); err != nil {
				return err
			}
			fmt.Fprintf(c.out, "removed profile: %s\n", name)
			return nil
		},
	}
}

func (c *CLI) emitProfile(name string, p *Profile) error {
	v := struct {
		Name       string `json:"name"`
		Endpoint   string `json:"endpoint"`
		Tenant     string `json:"tenant,omitempty"`
		APIKeyEnv  string `json:"api_key_env"`
		APIKeyFile string `json:"api_key_file,omitempty"`
	}{Name: name, Endpoint: p.Endpoint, Tenant: p.Tenant, APIKeyEnv: p.apiKeyEnvName(), APIKeyFile: p.APIKeyFile}
	tbl := table{
		Headers: []string{"FIELD", "VALUE"},
		Rows: [][]string{
			{"name", name},
			{"endpoint", p.Endpoint},
			{"tenant", p.Tenant},
			{"api_key_env", p.apiKeyEnvName()},
			{"api_key_file", p.APIKeyFile},
		},
	}
	return c.emit(v, tbl)
}
