# Protocol and identity boundaries

The listener is fixed to a provider, engine, instance, and upstream. TLS precedes token delivery. An authenticated fixture principal maps to one configured backend account, whose SQL grants determine query privileges. PostgreSQL startup and cancellation and MySQL handshake are handled before raw session forwarding. Login tokens are validated at connection setup; expiry does not terminate established sessions.

AWS RDS tokens are SigV4 presigned URLs generated locally by the real AWS CLI from mock IMDSv2 or ECS task credentials. Google tokens are opaque fixture values issued by metadata or OAuth refresh endpoints. Azure tokens are signed JWTs issued by the mock managed identity or OAuth endpoint and checked for tenant, audience, expiry, signature, and grants.

Embedding (`iamproxy.Start`) keeps these boundaries: in-memory dials route only to configured listeners, and the upstream dialer only ever receives a configured upstream. PostgreSQL CancelRequest arrives over TLS from pgx and libpq 17+. MySQL sessions fail with error 1235 when upstream and client negotiated different framing capabilities, because the frontend handshake precedes the upstream connection.
