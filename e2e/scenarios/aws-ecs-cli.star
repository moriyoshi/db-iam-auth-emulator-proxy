load("common.star", "aws_ecs_env")

postgres()
mysql()
proxy = start_proxy()

set_env(aws_ecs_env(proxy), unset_prefixes=["AWS_"])
for engine in ["postgres", "mysql"]:
    port = proxy["aws-" + engine].split(":")[1]
    credential = spawn([
        "aws", "rds", "generate-db-auth-token",
        "--hostname", "127.0.0.1", "--port", port,
        "--region", "us-east-1", "--username", "alice",
    ])
    assert_eq(query("aws", engine, credential, "select 1"), "1")
    log("AWS CLI via ECS task credentials authenticated to " + engine)
