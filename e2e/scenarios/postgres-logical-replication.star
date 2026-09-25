load("common.star", "aws_imds_env")

# Logical replication clients open the session with replication=database.
# pg_recvlogical and psql authenticate to the proxy with an RDS IAM token, and
# the fixture PostgreSQL runs with wal_level=logical.
postgres()
mariadb()
proxy = start_proxy()

set_env(aws_imds_env(proxy), unset_prefixes=["AWS_"])
port = proxy["aws-postgres"].split(":")[1]
credential = spawn([
    "aws", "rds", "generate-db-auth-token",
    "--hostname", "127.0.0.1", "--port", port,
    "--region", "us-east-1", "--username", "alice",
])
conninfo = "host=127.0.0.1 port=" + port + " dbname=testdb user=alice sslmode=require password='" + credential + "'"

spawn(["psql", conninfo, "-qAt", "-c", "create table repl_probe (id serial primary key, marker text not null)"])
identity = spawn(["psql", conninfo + " replication=database", "-qAt", "-c", "IDENTIFY_SYSTEM"])
assert_true(identity.endswith("|testdb"))
log("IDENTIFY_SYSTEM through proxy: " + identity)

spawn(["pg_recvlogical", "-d", conninfo, "--slot", "proxy_probe", "--create-slot", "--plugin", "test_decoding"])
lsn = spawn(["psql", conninfo, "-qAt", "-c", "insert into repl_probe (marker) values ('through-proxy')", "-c", "select pg_current_wal_lsn()"])
changes = spawn(["pg_recvlogical", "-d", conninfo, "--slot", "proxy_probe", "--start", "--endpos", lsn, "--no-loop", "-f", "-"])
assert_true("table public.repl_probe: INSERT:" in changes and "'through-proxy'" in changes)
log("pg_recvlogical streamed the insert through the proxy")
spawn(["pg_recvlogical", "-d", conninfo, "--slot", "proxy_probe", "--drop-slot"])

assert_eq(query("aws", "postgres", credential, "select count(*) from repl_probe where marker = 'through-proxy'"), "1")
log("Normal PostgreSQL session still works alongside replication")
