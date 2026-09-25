package iamproxy_test

import (
	"context"
	"log"

	"github.com/moriyoshi/db-iam-auth-emulator-proxy/iamproxy"
)

// Start an emulator on ephemeral loopback ports in front of a local
// PostgreSQL server.
func ExampleStart() {
	ctx := context.Background()
	e, err := iamproxy.Start(ctx, &iamproxy.Config{
		Listeners: []iamproxy.Listener{{
			Name: "orders", Listen: "127.0.0.1:0", Provider: "aws", Engine: "postgres",
			Instance: "orders", Hostname: "orders.cluster.us-east-1.rds.amazonaws.com",
			Region: "us-east-1", ResourceID: "db-orders", Upstream: "127.0.0.1:5432",
		}},
		Principals: []iamproxy.Principal{{ID: "app", Grants: []string{"orders"},
			BackendUser: "app", BackendPassword: "secret",
			AWSAccessKey: "AKIATEST", AWSSecretKey: "test-secret"}},
	}, iamproxy.Options{})
	if err != nil {
		log.Fatal(err)
	}
	defer e.Close()
	addr, _ := e.ListenerAddr("orders") // bound loopback address
	imds := e.HTTPURL() + "/"           // AWS_EC2_METADATA_SERVICE_ENDPOINT
	log.Println(addr, imds)
}
