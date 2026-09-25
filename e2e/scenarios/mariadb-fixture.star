load("common.star", "aws_imds_env")

postgres()
mariadb()
proxy = start_proxy()

set_env(aws_imds_env(proxy), unset_prefixes=["AWS_"])
port = proxy["aws-mysql"].split(":")[1]
credential = spawn([
    "aws", "rds", "generate-db-auth-token",
    "--hostname", "127.0.0.1", "--port", port,
    "--region", "us-east-1", "--username", "alice",
])
assert_eq(query("aws", "mysql", credential, "select 1"), "1")
log("AWS CLI IAM login through MariaDB passed")
