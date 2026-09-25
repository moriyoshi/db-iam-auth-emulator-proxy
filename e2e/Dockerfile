# One image runs every scenario and all three database fixture modes. Cloud
# CLIs and the Docker client are dependencies of the image, not the host.
FROM docker:29.2.1-cli@sha256:cab69e2d0a1a2ea9a1ce1060252f439e83483ae41ec09317aecb33b08a0656a5 AS docker-cli
FROM mysql:8.4 AS mysql-fixture
FROM mariadb:10.11 AS mariadb-fixture

FROM postgres:17-bookworm
RUN apt-get update && \
    apt-get install -y --no-install-recommends awscli ca-certificates curl gnupg libaio1 mariadb-server && \
    curl -fsSL https://packages.cloud.google.com/apt/doc/apt-key.gpg | gpg --dearmor -o /usr/share/keyrings/google-cloud.gpg && \
    echo "deb [signed-by=/usr/share/keyrings/google-cloud.gpg] https://packages.cloud.google.com/apt cloud-sdk main" > /etc/apt/sources.list.d/google-cloud-sdk.list && \
    curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor -o /usr/share/keyrings/microsoft.gpg && \
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/azure-cli/ bookworm main" > /etc/apt/sources.list.d/azure-cli.list && \
    apt-get update && \
    apt-get install -y --no-install-recommends google-cloud-cli azure-cli && \
    rm -rf /var/lib/apt/lists/* /var/lib/mysql/*

COPY --from=docker-cli /usr/local/bin/docker /usr/local/bin/docker
COPY --from=mysql-fixture /usr/sbin/mysqld /opt/mysql/sbin/mysqld
COPY --from=mysql-fixture /usr/bin/mysql /opt/mysql/bin/mysql
COPY --from=mysql-fixture /usr/bin/mysqladmin /opt/mysql/bin/mysqladmin
COPY --from=mysql-fixture /usr/lib64/mysql /opt/mysql/lib64/mysql
COPY --from=mysql-fixture /usr/share/mysql-8.4 /opt/mysql/share/mysql-8.4
COPY --from=mysql-fixture /usr/local/bin/docker-entrypoint.sh /usr/local/bin/mysql-docker-entrypoint.sh
COPY --from=mariadb-fixture /usr/sbin/mariadbd /usr/sbin/mariadbd
COPY --from=mariadb-fixture /usr/bin/mariadb /usr/bin/mariadb
COPY --from=mariadb-fixture /usr/bin/mariadb-admin /usr/bin/mariadb-admin
COPY --from=mariadb-fixture /usr/bin/mariadb-install-db /usr/bin/mariadb-install-db
COPY --from=mariadb-fixture /usr/bin/my_print_defaults /usr/bin/my_print_defaults
COPY --from=mariadb-fixture /usr/bin/resolveip /usr/bin/resolveip
COPY --from=mariadb-fixture /usr/lib/mysql /usr/lib/mysql
COPY --from=mariadb-fixture /usr/share/mysql /usr/share/mysql
COPY .agents-workspace/tmp/db-iam-auth-emulator-proxy /usr/local/bin/db-iam-auth-emulator-proxy
COPY .agents-workspace/tmp/db-iam-auth-emulator-proxy-e2e /usr/local/bin/db-iam-auth-emulator-proxy-e2e
COPY e2e/scenarios /workspace/e2e/scenarios
COPY e2e/entrypoint.sh /usr/local/bin/iam-proxy-e2e-entrypoint
RUN chmod 0755 /usr/local/bin/iam-proxy-e2e-entrypoint /usr/local/bin/mysql-docker-entrypoint.sh
WORKDIR /workspace
ENTRYPOINT ["/usr/local/bin/iam-proxy-e2e-entrypoint"]
