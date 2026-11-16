# A Python program's work: JSON, regular expressions, dictionaries, sorting.
import json
import re

records = [{"id": i, "name": f"item-{i}", "tags": [f"t{i % 7}", f"t{i % 11}"], "value": i * 0.5}
           for i in range(60000)]
text = json.dumps(records)
back = json.loads(text)
total = sum(r["value"] for r in back)

counts = {}
for m in re.finditer(r'"name": "item-(\d+)"', text):
    k = int(m.group(1)) % 97
    counts[k] = counts.get(k, 0) + 1

words = ("lorem ipsum dolor sit amet consectetur adipiscing elit " * 40000).split()
freq = {}
for w in words:
    freq[w] = freq.get(w, 0) + 1
ranked = sorted(back, key=lambda r: (r["tags"][1], -r["id"]))
print(int(total), len(counts), freq["lorem"], ranked[0]["id"])
