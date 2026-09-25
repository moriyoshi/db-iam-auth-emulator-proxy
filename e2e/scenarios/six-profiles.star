load("common.star", "aws_imds_env", "google_env", "azure_env")

postgres()
mysql()
proxy = start_proxy()

set_env(aws_imds_env(proxy), unset_prefixes=["AWS_"])
for engine in ["postgres", "mysql"]:
    port = proxy["aws-" + engine].split(":")[1]
    token = spawn([
        "aws", "rds", "generate-db-auth-token",
        "--hostname", "127.0.0.1", "--port", port,
        "--region", "us-east-1", "--username", "alice",
    ])
    assert_eq(query("aws", engine, token, "select 1"), "1")
    log("AWS CLI " + engine + " login and SQL passed")

set_env(google_env(proxy), unset_prefixes=["GOOGLE_", "CLOUDSDK_"])
for engine in ["postgres", "mysql"]:
    token = spawn(["gcloud", "auth", "application-default", "print-access-token"])
    assert_eq(query("google", engine, token, "select 1"), "1")
    log("Google Cloud CLI " + engine + " login and SQL passed")

set_env(azure_env(proxy), unset_prefixes=["AZURE_", "IDENTITY_", "MSI_"])
spawn([
    "az", "cloud", "register", "--name", "IAMProxyMock",
    "--endpoint-resource-manager", proxy["https"] + "/arm/",
    "--endpoint-active-directory", proxy["https"] + "/",
    "--endpoint-active-directory-resource-id", "https://management.azure.com/",
    "--skip-endpoint-discovery", "--output", "none",
])
spawn(["az", "cloud", "set", "--name", "IAMProxyMock"])
spawn(["az", "login", "--identity", "--client-id", "client-1", "--allow-no-subscriptions", "--output", "none"])
for engine in ["postgres", "mysql"]:
    token = spawn([
        "az", "account", "get-access-token", "--resource", "https://ossrdbms-aad.database.windows.net",
        "--query", "accessToken", "--output", "tsv",
    ])
    assert_eq(query("azure", engine, token, "select 1"), "1")
    log("Azure CLI " + engine + " login and SQL passed")
