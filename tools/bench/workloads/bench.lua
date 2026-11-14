-- A Lua program's work: recursion, tables, sorting and strings.
local function fib(n) if n < 2 then return n end return fib(n - 1) + fib(n - 2) end
local sum = fib(30)

local t = {}
for i = 1, 1000000 do t[i] = (i * 7919) % 1000003 end
table.sort(t)
for i = 1, #t, 1000 do sum = sum + t[i] end

local parts = {}
for i = 1, 300000 do parts[#parts + 1] = string.format("%d:%x", i, i * 31) end
local s = table.concat(parts, ",")
local n = 0
for a, b in s:gmatch("(%d+):(%x+)") do n = n + #a + #b end
local words = {}
for w in ("the quick brown fox jumps over the lazy dog "):rep(60000):gmatch("%a+") do
  words[w] = (words[w] or 0) + 1
end
print(sum + n + words.the)
