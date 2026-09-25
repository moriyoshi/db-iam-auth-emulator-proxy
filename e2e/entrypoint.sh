#!/usr/bin/env bash
set -euo pipefail

if [[ "${1:-}" != "--database" ]]; then
    exec /usr/local/bin/db-iam-auth-emulator-proxy-e2e "$@"
fi

engine="${2:-}"
case "$engine" in
    postgres)
        exec /usr/local/bin/docker-entrypoint.sh postgres
        ;;
    mysql)
        mv /etc/mysql /etc/mysql-disabled
        mkdir -p /usr/lib64/mysql
        ln -s /opt/mysql/lib64/mysql/private /usr/lib64/mysql/private
        export PATH="/opt/mysql/sbin:/opt/mysql/bin:$PATH"
        export LD_LIBRARY_PATH="/opt/mysql/lib64/mysql/private${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}"
        export MYSQL_INITDB_SKIP_TZINFO=1
        exec /usr/local/bin/mysql-docker-entrypoint.sh mysqld --no-defaults --lc-messages-dir=/opt/mysql/share/mysql-8.4 --mysqlx=OFF
        ;;
    mariadb)
        datadir=/var/lib/mariadb-e2e
        socket=/run/mysqld/mariadb-e2e.sock
        mkdir -p "$datadir" /run/mysqld
        chown -R mysql:mysql "$datadir" /run/mysqld
        mariadb-install-db --user=mysql --datadir="$datadir" --skip-test-db >/dev/null
        mariadbd --user=mysql --datadir="$datadir" --socket="$socket" --skip-networking &
        pid=$!
        for i in $(seq 1 100); do
            if mariadb-admin --socket="$socket" ping >/dev/null 2>&1; then break; fi
            sleep 0.1
        done
        mariadb --socket="$socket" -uroot <<SQL
CREATE DATABASE IF NOT EXISTS testdb;
CREATE USER IF NOT EXISTS 'backend'@'%' IDENTIFIED BY 'backpass';
GRANT ALL ON testdb.* TO 'backend'@'%';
FLUSH PRIVILEGES;
SQL
        mariadb-admin --socket="$socket" -uroot shutdown
        wait "$pid"
        exec mariadbd --user=mysql --datadir="$datadir" --socket="$socket" --bind-address=0.0.0.0 --port=3306
        ;;
    *)
        echo "unknown database engine: $engine" >&2
        exit 2
        ;;
esac
