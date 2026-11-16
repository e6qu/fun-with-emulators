# A repository's work: commits over a source tree, its history read with
# patches, status looked at again and again, and a repack.
# Run in an empty directory, with a C source directory at "$1" and git as
# "$2".
set -e
git="$2"
mkdir src
cp "$1"/*.c "$1"/*.h src/
"$git" init -q
"$git" config user.name bench
"$git" config user.email bench@example.invalid
# Only the repack below: a commit can start one of its own in the
# background (git's count of loose objects is an estimate), which would
# race that one.
"$git" config gc.auto 0
# Nor the maintenance a commit can start after itself (git versions differ
# in whether they do): both sides do the same work.
"$git" config maintenance.auto false
"$git" add -A
"$git" commit -q -m initial
i=0
for f in src/*.c; do
    i=$((i + 1))
    [ $i -gt 60 ] && break
    echo "/* change $i */" >> "$f"
    "$git" commit -q -am "change $i"
done
"$git" log -p > /dev/null
j=0
while [ $j -lt 30 ]; do
    "$git" status --porcelain > /dev/null
    j=$((j + 1))
done
"$git" gc -q
"$git" rev-list --count HEAD
