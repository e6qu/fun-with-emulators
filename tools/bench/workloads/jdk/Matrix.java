import java.util.concurrent.ForkJoinPool;
import java.util.concurrent.RecursiveTask;

/** A product of two integer matrices, split by rows into fork/join tasks;
 *  integer arithmetic, so the checksum is exact on every platform. */
final class Matrix {
    private static final long MOD = 1_000_000_007L;

    static long[][] random(int n, long seed) {
        Rng rng = new Rng(seed);
        long[][] m = new long[n][n];
        for (long[] row : m) {
            for (int j = 0; j < n; j++) {
                row[j] = rng.below(1000);
            }
        }
        return m;
    }

    private static final class Rows extends RecursiveTask<Long> {
        private final long[][] a;
        private final long[][] b;
        private final int from;
        private final int to;

        Rows(long[][] a, long[][] b, int from, int to) {
            this.a = a;
            this.b = b;
            this.from = from;
            this.to = to;
        }

        @Override
        protected Long compute() {
            if (to - from > 16) {
                int mid = (from + to) >>> 1;
                Rows left = new Rows(a, b, from, mid);
                left.fork();
                long right = new Rows(a, b, mid, to).compute();
                return (left.join() + right) % MOD;
            }
            int n = b.length;
            long sum = 0;
            for (int i = from; i < to; i++) {
                for (int j = 0; j < n; j++) {
                    long cell = 0;
                    for (int k = 0; k < n; k++) {
                        cell += a[i][k] * b[k][j];
                    }
                    sum = (sum * 31 + cell) % MOD;
                }
            }
            return sum;
        }
    }

    static String run(int n, int rounds) {
        long checksum = 0;
        for (int r = 0; r < rounds; r++) {
            long[][] a = random(n, 2 * r + 1);
            long[][] b = random(n, 2 * r + 2);
            checksum = (checksum + ForkJoinPool.commonPool().invoke(new Rows(a, b, 0, n))) % MOD;
        }
        return "matrix " + n + "x" + n + " x" + rounds + ": checksum " + checksum;
    }
}
