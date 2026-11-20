import java.util.ArrayList;
import java.util.BitSet;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;

/** Primes below a limit, the range sieved in segments by a fixed pool of
 *  threads, each segment marking its own BitSet. */
final class Primes {
    static String run(int limit, int threads) throws Exception {
        int root = (int) Math.sqrt(limit);
        BitSet small = new BitSet(root + 1);
        small.set(2, root + 1);
        for (int p = 2; p * p <= root; p++) {
            if (small.get(p)) {
                for (int q = p * p; q <= root; q += p) {
                    small.clear(q);
                }
            }
        }
        int segment = 1 << 18;
        ExecutorService pool = Executors.newFixedThreadPool(threads);
        try {
            List<Future<long[]>> parts = new ArrayList<>();
            for (int low = 0; low < limit; low += segment) {
                final int lo = low;
                final int hi = Math.min(limit, low + segment);
                parts.add(pool.submit(() -> sieve(small, lo, hi)));
            }
            long count = 0;
            long sum = 0;
            for (Future<long[]> part : parts) {
                long[] r = part.get();
                count += r[0];
                sum += r[1];
            }
            return "primes below " + limit + ": " + count + ", sum " + sum;
        } finally {
            pool.shutdown();
        }
    }

    private static long[] sieve(BitSet small, int lo, int hi) {
        BitSet composite = new BitSet(hi - lo);
        for (int p = small.nextSetBit(2); p >= 0; p = small.nextSetBit(p + 1)) {
            long start = Math.max((long) p * p, ((lo + p - 1L) / p) * p);
            for (long q = start; q < hi; q += p) {
                composite.set((int) (q - lo));
            }
        }
        long count = 0;
        long sum = 0;
        for (int n = Math.max(lo, 2); n < hi; n++) {
            if (!composite.get(n - lo)) {
                count++;
                sum += n;
            }
        }
        return new long[] {count, sum};
    }
}
