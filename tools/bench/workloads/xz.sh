# Compression's work: a file of text, compressed and decompressed.
# Run in an empty directory, with a C source directory at "$1" and xz as
# "$2": the sources, 20 times over with a counter between copies, about
# 13 MiB.
set -e
xz="$2"
cat "$1"/*.c > one
i=0
: > data
while [ $i -lt 20 ]; do
    cat one >> data
    echo "copy $i" >> data
    i=$((i + 1))
done
"$xz" -6 -T1 -k data
"$xz" -d -T1 -c data.xz > back
cmp data back
echo $(( $(wc -c < data.xz) ))
