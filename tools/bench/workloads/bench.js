// A JavaScript program's work: recursion, objects and classes, arrays and
// sorting, strings, regular expressions, maps and JSON.
function fib(n) { return n < 2 ? n : fib(n - 1) + fib(n - 2); }
let sum = fib(32);

class Point {
  constructor(x, y) { this.x = x; this.y = y; }
  add(o) { return new Point(this.x + o.x, this.y + o.y); }
  get norm() { return Math.abs(this.x) + Math.abs(this.y); }
}
let p = new Point(0, 0);
for (let i = 0; i < 6000000; i++) p = p.add(new Point(i % 7 - 3, i % 5 - 2));
sum += p.norm;

const t = [];
for (let i = 1; i <= 2000000; i++) t.push((i * 7919) % 1000003);
t.sort((a, b) => a - b);
for (let i = 0; i < t.length; i += 1000) sum += t[i];

const parts = [];
for (let i = 1; i <= 600000; i++) parts.push(`${i}:${(i * 31).toString(16)}`);
const s = parts.join(",");
let n = 0;
for (const m of s.matchAll(/(\d+):([0-9a-f]+)/g)) n += m[1].length + m[2].length;

const words = new Map();
for (const w of "the quick brown fox jumps over the lazy dog ".repeat(200000).match(/[a-z]+/g)) {
  words.set(w, (words.get(w) || 0) + 1);
}

const records = [];
for (let i = 0; i < 150000; i++) records.push({ id: i, name: `item${i}`, tags: [i % 3, i % 5], ok: i % 2 === 0 });
const back = JSON.parse(JSON.stringify(records));
const kept = back.filter((r) => r.ok).map((r) => r.tags[0] + r.tags[1]).reduce((a, b) => a + b, 0);

console.log(sum + n + words.get("the") + kept);
