package iamproxy

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/goccy/go-yaml"
)

type Config struct {
	HTTPListen  string      `yaml:"http_listen,omitempty"`
	HTTPSListen string      `yaml:"https_listen,omitempty"`
	PublicURL   string      `yaml:"public_url,omitempty"`
	TLSCert     string      `yaml:"tls_cert,omitempty"`
	TLSKey      string      `yaml:"tls_key,omitempty"`
	Listeners   []Listener  `yaml:"listeners,omitempty"`
	Principals  []Principal `yaml:"principals,omitempty"`
}

type Listener struct {
	Name        string `yaml:"name,omitempty"`
	Listen      string `yaml:"listen,omitempty"`
	Provider    string `yaml:"provider,omitempty"`
	Engine      string `yaml:"engine,omitempty"`
	Instance    string `yaml:"instance,omitempty"`
	Hostname    string `yaml:"hostname,omitempty"`
	Region      string `yaml:"region,omitempty"`
	ResourceID  string `yaml:"resource_id,omitempty"`
	Tenant      string `yaml:"tenant,omitempty"`
	Upstream    string `yaml:"upstream,omitempty"`
	UpstreamTLS string `yaml:"upstream_tls,omitempty"`
}

type Principal struct {
	ID                    string   `yaml:"id,omitempty"`
	Email                 string   `yaml:"email,omitempty"`
	Groups                []string `yaml:"groups,omitempty"`
	Grants                []string `yaml:"grants,omitempty"` // listener names
	BackendUser           string   `yaml:"backend_user,omitempty"`
	BackendPassword       string   `yaml:"backend_password,omitempty"`
	AWSAccessKey          string   `yaml:"aws_access_key,omitempty"`
	AWSSecretKey          string   `yaml:"aws_secret_key,omitempty"`
	AWSSessionToken       string   `yaml:"aws_session_token,omitempty"`
	ECSAuthorizationToken string   `yaml:"ecs_authorization_token,omitempty"`
	GoogleRefreshToken    string   `yaml:"google_refresh_token,omitempty"`
	AzureClientID         string   `yaml:"azure_client_id,omitempty"`
	AzureClientSecret     string   `yaml:"azure_client_secret,omitempty"`
}

func LoadConfig(path string) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	c, err := ParseConfig(b)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return c, nil
}

// ParseConfig decodes one YAML document, rejecting unknown fields, and
// validates it.
func ParseConfig(b []byte) (*Config, error) {
	var c Config
	dec := yaml.NewDecoder(bytes.NewReader(b), yaml.DisallowUnknownField())
	if err := dec.Decode(&c); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("configuration is empty")
		}
		return nil, err
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, errors.New("configuration must contain exactly one YAML document")
	}
	if err := c.Validate(); err != nil {
		return nil, err
	}
	return &c, nil
}

func (c *Config) Validate() error {
	if c.HTTPListen == "" {
		c.HTTPListen = "127.0.0.1:8090"
	}
	if !loopbackAddress(c.HTTPListen) {
		return errors.New("credential endpoint must bind to loopback")
	}
	if c.HTTPSListen != "" && !loopbackAddress(c.HTTPSListen) {
		return errors.New("TLS credential endpoint must bind to loopback")
	}
	if (c.TLSCert == "") != (c.TLSKey == "") {
		return errors.New("tls_cert and tls_key must both be set")
	}
	if len(c.Listeners) == 0 {
		return errors.New("at least one listener is required")
	}
	listeners := map[string]bool{}
	addresses := map[string]bool{c.HTTPListen: true}
	if c.HTTPSListen != "" {
		if _, port, _ := net.SplitHostPort(c.HTTPSListen); port != "0" && addresses[c.HTTPSListen] {
			return errors.New("duplicate credential endpoint address")
		}
		addresses[c.HTTPSListen] = true
	}
	for _, l := range c.Listeners {
		if l.Name == "" || l.Listen == "" || l.Upstream == "" || l.Instance == "" {
			return fmt.Errorf("listener %q missing required field", l.Name)
		}
		if l.Provider != "aws" && l.Provider != "google" && l.Provider != "azure" {
			return fmt.Errorf("listener %s: invalid provider", l.Name)
		}
		if l.Engine != "postgres" && l.Engine != "mysql" {
			return fmt.Errorf("listener %s: invalid engine", l.Name)
		}
		_, port, err := net.SplitHostPort(l.Listen)
		if err != nil {
			return fmt.Errorf("listener %s: %w", l.Name, err)
		}
		if listeners[l.Name] || port != "0" && addresses[l.Listen] {
			return fmt.Errorf("duplicate listener name or address: %s", l.Name)
		}
		if l.Provider == "aws" && (l.Hostname == "" || l.Region == "" || l.ResourceID == "") {
			return fmt.Errorf("listener %s: AWS requires hostname, region and resource_id", l.Name)
		}
		if l.Provider == "azure" && l.Tenant == "" {
			return fmt.Errorf("listener %s: Azure requires tenant", l.Name)
		}
		if l.UpstreamTLS != "" && l.UpstreamTLS != "disable" && l.UpstreamTLS != "require" && l.UpstreamTLS != "verify-full" {
			return fmt.Errorf("listener %s: invalid upstream_tls", l.Name)
		}
		if !loopbackAddress(l.Listen) {
			return fmt.Errorf("listener %s: only loopback binds are supported", l.Name)
		}
		listeners[l.Name], addresses[l.Listen] = true, true
	}
	ids := map[string]bool{}
	keys := map[string]bool{}
	backendUsers := map[string]string{}
	googleNames := map[string]string{}
	azureNames := map[string]string{}
	byName := map[string]Listener{}
	for _, l := range c.Listeners {
		byName[l.Name] = l
	}
	for _, p := range c.Principals {
		if p.ID == "" || p.BackendUser == "" || p.BackendPassword == "" {
			return fmt.Errorf("principal %s: id and backend credentials required", p.ID)
		}
		if ids[p.ID] {
			return fmt.Errorf("duplicate principal %s", p.ID)
		}
		ids[p.ID] = true
		if p.AWSAccessKey != "" {
			if p.AWSSecretKey == "" || keys[p.AWSAccessKey] {
				return fmt.Errorf("principal %s: invalid AWS key", p.ID)
			}
			keys[p.AWSAccessKey] = true
		}
		if p.ECSAuthorizationToken != "" && p.AWSAccessKey == "" {
			return fmt.Errorf("principal %s: ECS authorization token requires AWS credentials", p.ID)
		}
		for _, g := range p.Grants {
			if !listeners[g] {
				return fmt.Errorf("principal %s: unknown listener grant %s", p.ID, g)
			}
			l := byName[g]
			backendKey := g + "\x00" + p.BackendUser
			if other := backendUsers[backendKey]; other != "" && other != p.ID {
				return fmt.Errorf("listener %s: backend user %s is shared by principals", g, p.BackendUser)
			}
			backendUsers[backendKey] = p.ID
			if l.Provider == "google" {
				if p.Email == "" {
					return fmt.Errorf("principal %s: Google email required", p.ID)
				}
				key := g + "\x00" + googleUsername(p.Email, l.Engine)
				if other := googleNames[key]; other != "" && other != p.ID {
					return fmt.Errorf("listener %s: ambiguous Google database username", g)
				}
				googleNames[key] = p.ID
			}
			if l.Provider == "azure" {
				if p.Email == "" {
					return fmt.Errorf("principal %s: Azure email required", p.ID)
				}
				key := g + "\x00" + p.Email
				if other := azureNames[key]; other != "" && other != p.ID {
					return fmt.Errorf("listener %s: duplicate Azure username", g)
				}
				azureNames[key] = p.ID
			}
		}
	}
	return nil
}

// clone returns a deep copy, so a running emulator never shares slices with
// its caller.
func (c *Config) clone() *Config {
	d := *c
	d.Listeners = append([]Listener(nil), c.Listeners...)
	d.Principals = append([]Principal(nil), c.Principals...)
	for i := range d.Principals {
		d.Principals[i].Groups = append([]string(nil), c.Principals[i].Groups...)
		d.Principals[i].Grants = append([]string(nil), c.Principals[i].Grants...)
	}
	return &d
}

func loopbackAddress(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return false
	}
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (p *Principal) Granted(listener string) bool {
	for _, g := range p.Grants {
		if g == listener {
			return true
		}
	}
	return false
}
