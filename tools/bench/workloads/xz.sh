# Compression's work: a file of text, compressed and decompressed.
# Run in an empty directory, with a C source directory at "$1" and xz as
# "$2": the sources, again and again, with a counter between copies, make
# 12 MiB.
set -e
xz="$2"
i=0
: > data
while [ "$(wc -c < data)" -lt 12582912 ]; do
    cat "$1"/*.c >> data
    echo "copy $i" >> data
    i=$((i + 1))
done
"$xz" -6 -T1 -k data
"$xz" -d -T1 -c data.xz > back
cmp data back
echo $(( $(wc -c < data.xz) ))
