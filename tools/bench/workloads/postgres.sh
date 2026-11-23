# PostgreSQL at work, a System V user: a cluster made, started on a socket
# in the working directory (its System V segment, its shared memory, its
# semaphores, a process for each client), filled by pgbench and run by
# four clients at once, then stopped.
# Run in an empty directory, with PostgreSQL's programs in "$1". Prints the
# transactions the clients ran and the rows pgbench made.
set -e
bin="$1"
"$bin/initdb" -D pg -A trust -U bench -E UTF8 --locale=C --no-sync >/dev/null
"$bin/pg_ctl" -D pg -w -l pg.log -o "-k $PWD -c listen_addresses= -c fsync=off" start >/dev/null
trap '"$bin/pg_ctl" -D pg -m fast -w stop >/dev/null' EXIT
"$bin/pgbench" -h "$PWD" -U bench -i -q -s 2 postgres 2>/dev/null
"$bin/pgbench" -h "$PWD" -U bench -c 4 -j 2 -t 250 postgres 2>/dev/null |
    grep "^number of transactions actually processed"
"$bin/psql" -h "$PWD" -U bench -At -c "select count(*) from pgbench_accounts" postgres
