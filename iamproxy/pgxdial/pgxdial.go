// Package pgxdial routes pgx and pgconn connections to an embedded emulator
// in memory.
package pgxdial

import (
	"context"
	"crypto/tls"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
)

// Configure makes cfg dial e in memory. Host names reach the emulator
// unresolved, so a DSN can name a listener's cloud hostname. TLS
// configurations without RootCAs, including fallbacks, are cloned to trust
// e's certificate. Use &connConfig.Config for pgx.ConnConfig.
func Configure(cfg *pgconn.Config, e *iamproxy.Emulator) {
	cfg.DialFunc = e.DialContext
	cfg.LookupFunc = func(_ context.Context, host string) ([]string, error) { return []string{host}, nil }
	cfg.TLSConfig = trust(cfg.TLSConfig, e)
	for _, f := range cfg.Fallbacks {
		f.TLSConfig = trust(f.TLSConfig, e)
	}
}

func trust(c *tls.Config, e *iamproxy.Emulator) *tls.Config {
	if c == nil || c.RootCAs != nil {
		return c
	}
	c = c.Clone()
	c.RootCAs = e.CertPool()
	return c
}
