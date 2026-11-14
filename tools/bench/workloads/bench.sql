-- A database's work, on disk: a bulk insert in a transaction, an index,
-- queries, an update and a delete.
PRAGMA journal_mode = WAL;
CREATE TABLE items (id INTEGER PRIMARY KEY, name TEXT, grp INTEGER, value REAL);
BEGIN;
WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 300000)
INSERT INTO items (name, grp, value) SELECT 'item-' || i, i % 113, i * 0.25 FROM n;
COMMIT;
CREATE INDEX items_grp ON items (grp);
SELECT grp, count(*), sum(value) FROM items GROUP BY grp ORDER BY 3 DESC LIMIT 3;
SELECT count(*) FROM items WHERE name LIKE 'item-1%';
SELECT avg(value) FROM items WHERE grp BETWEEN 10 AND 20;
UPDATE items SET value = value * 2 WHERE grp % 3 = 0;
DELETE FROM items WHERE grp = 7;
SELECT count(*), sum(value) FROM items;
