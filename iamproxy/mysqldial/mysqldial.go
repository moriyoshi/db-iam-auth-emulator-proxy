// Package mysqldial routes go-sql-driver/mysql connections to an embedded
// emulator in memory.
package mysqldial

import (
	"context"
	"net"

	"github.com/go-sql-driver/mysql"
	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
)

// Register registers name as both a network and a TLS configuration in the
// driver's global registries. A DSN such as
//
//	alice:TOKEN@name(db.example:3306)/testdb?tls=name&allowCleartextPasswords=true
//
// then reaches e in memory and verifies its certificate against the host.
// Registering a name again replaces its earlier emulator. The driver cannot
// remove a network, so give concurrently running emulators distinct names.
func Register(name string, e *iamproxy.Emulator) error {
	if err := mysql.RegisterTLSConfig(name, e.ClientTLSConfig()); err != nil {
		return err
	}
	mysql.RegisterDialContext(name, func(ctx context.Context, addr string) (net.Conn, error) {
		return e.DialContext(ctx, "tcp", addr)
	})
	return nil
}
