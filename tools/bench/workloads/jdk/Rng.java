/** A small deterministic random number generator (SplitMix64), so every
 *  run sees the same data whatever the platform. */
final class Rng {
    private long state;

    Rng(long seed) {
        state = seed;
    }

    long next() {
        long z = (state += 0x9E3779B97F4A7C15L);
        z = (z ^ (z >>> 30)) * 0xBF58476D1CE4E5B9L;
        z = (z ^ (z >>> 27)) * 0x94D049BB133111EBL;
        return z ^ (z >>> 31);
    }

    int below(int n) {
        return (int) Long.remainderUnsigned(next(), n);
    }
}
