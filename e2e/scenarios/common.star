def aws_imds_env(proxy):
    return {
        "AWS_CONFIG_FILE": proxy["aws_config"],
        "AWS_SHARED_CREDENTIALS_FILE": proxy["aws_config"],
        "AWS_EC2_METADATA_SERVICE_ENDPOINT": proxy["http"] + "/",
        "AWS_EC2_METADATA_V1_DISABLED": "true",
        "AWS_EC2_METADATA_DISABLED": "false",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_PAGER": "",
        "NO_PROXY": "127.0.0.1,localhost",
    }

def aws_ecs_env(proxy):
    return {
        "AWS_CONFIG_FILE": proxy["aws_config"],
        "AWS_SHARED_CREDENTIALS_FILE": proxy["aws_config"],
        "AWS_CONTAINER_CREDENTIALS_FULL_URI": proxy["http"] + "/v2/credentials/alice",
        "AWS_CONTAINER_AUTHORIZATION_TOKEN": "ecs-auth",
        "AWS_EC2_METADATA_DISABLED": "true",
        "AWS_DEFAULT_REGION": "us-east-1",
        "AWS_PAGER": "",
        "ECS_CONTAINER_METADATA_URI_V4": proxy["http"] + "/ecs/v4/alice",
        "NO_PROXY": "127.0.0.1,localhost",
    }

def google_env(proxy):
    return {
        "GOOGLE_APPLICATION_CREDENTIALS": proxy["google_adc"],
        "CLOUDSDK_CONFIG": proxy["gcloud_config"],
        "CLOUDSDK_CORE_DISABLE_PROMPTS": "1",
        "CLOUDSDK_AUTH_TOKEN_HOST": proxy["http"] + "/token",
        "NO_PROXY": "127.0.0.1,localhost",
    }

def azure_env(proxy):
    return {
        "AZURE_CONFIG_DIR": proxy["azure_config"],
        "AZURE_POD_IDENTITY_AUTHORITY_HOST": proxy["http"],
        "AZURE_CORE_COLLECT_TELEMETRY": "no",
        "REQUESTS_CA_BUNDLE": proxy["cert"],
        "SSL_CERT_FILE": proxy["cert"],
        "NO_PROXY": "127.0.0.1,localhost",
    }
