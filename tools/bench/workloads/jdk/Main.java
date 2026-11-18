/** A multi-threaded workload for a JVM: text counted with parallel
 *  streams and regular expressions, primes sieved by a thread pool, a
 *  matrix product with fork/join, and lock-heavy transfers that keep the
 *  garbage collector busy. Its output is the same on every platform; the
 *  argument scales the work (1 is a quick run, the benchmark uses more).
 *  How long each part took goes to standard error. */
public final class Main {
    public static void main(String[] args) throws Exception {
        int scale = args.length > 0 ? Integer.parseInt(args[0]) : 1;
        long t = System.nanoTime();
        System.out.println(Words.run(64 * scale, 20_000));
        t = took("words", t);
        System.out.println(Primes.run(20_000_000 * scale, 4));
        t = took("primes", t);
        System.out.println(Matrix.run(160, 2 * scale));
        t = took("matrix", t);
        System.out.println(Bank.run(100, 8, 200_000 * scale));
        took("bank", t);
        System.out.println("done");
    }

    /** How long a part took since `since`, on standard error (its time is
     *  no part of the output), and the time now. */
    private static long took(String part, long since) {
        long now = System.nanoTime();
        System.err.println(part + " " + (now - since) / 1_000_000 + " ms");
        return now;
    }
}
