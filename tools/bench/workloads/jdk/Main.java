/** A multi-threaded workload for a JVM: text counted with parallel
 *  streams and regular expressions, primes sieved by a thread pool, a
 *  matrix product with fork/join, and lock-heavy transfers that keep the
 *  garbage collector busy. Its output is the same on every platform; the
 *  argument scales the work (1 is a quick run, the benchmark uses more). */
public final class Main {
    public static void main(String[] args) throws Exception {
        int scale = args.length > 0 ? Integer.parseInt(args[0]) : 1;
        System.out.println(Words.run(64 * scale, 20_000));
        System.out.println(Primes.run(20_000_000 * scale, 4));
        System.out.println(Matrix.run(160, 2 * scale));
        System.out.println(Bank.run(100, 8, 200_000 * scale));
        System.out.println("done");
    }
}
