# PostgreSQL at work, a System V user: a cluster made, started on a socket
# in the working directory (its System V segment, its shared memory, its
# semaphores, a process for each client), filled by pgbench and run by
# four clients at once, then stopped.
# Run in an empty directory, with PostgreSQL's programs in "$1". Prints the
# transactions the clients ran and the rows pgbench made; a step that fails
# is named, with the server's log, on the standard error.
bin="$1"
fail() {
    echo "postgres.sh: $1 failed (as $(id -un))" >&2
    [ -f pg.log ] && cat pg.log >&2
    exit 1
}
"$bin/initdb" -D pg -A trust -U bench -E UTF8 --locale=C --no-sync >/dev/null || fail initdb
"$bin/pg_ctl" -D pg -w -l pg.log -o "-k $PWD -c listen_addresses= -c fsync=off" start \
    >/dev/null || fail "the server's start"
trap '"$bin/pg_ctl" -D pg -m fast -w stop >/dev/null' EXIT
"$bin/pgbench" -h "$PWD" -U bench -i -q -s 2 postgres 2>/dev/null || fail "pgbench -i"
out=$("$bin/pgbench" -h "$PWD" -U bench -c 4 -j 2 -t 250 postgres 2>/dev/null) || fail pgbench
echo "$out" | grep "^number of transactions actually processed" || fail "pgbench's count"
"$bin/psql" -h "$PWD" -U bench -At -c "select count(*) from pgbench_accounts" postgres ||
    fail psql
