import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.locks.ReentrantLock;

/** Accounts moving money between each other from many threads, each
 *  transfer taking two locks in a fixed order, and keeping a history of
 *  short-lived records for the garbage collector; the total never changes. */
final class Bank {
    private static final class Account {
        final int id;
        final ReentrantLock lock = new ReentrantLock();
        long balance;
        List<long[]> history = new ArrayList<>();

        Account(int id, long balance) {
            this.id = id;
            this.balance = balance;
        }
    }

    static String run(int accounts, int threads, int transfers) throws InterruptedException {
        Account[] all = new Account[accounts];
        for (int i = 0; i < accounts; i++) {
            all[i] = new Account(i, 1_000);
        }
        AtomicLong moved = new AtomicLong();
        CountDownLatch done = new CountDownLatch(threads);
        for (int t = 0; t < threads; t++) {
            final Rng rng = new Rng(1_000 + t);
            Thread worker = new Thread(() -> {
                for (int i = 0; i < transfers; i++) {
                    Account from = all[rng.below(accounts)];
                    Account to = all[rng.below(accounts)];
                    if (from == to) {
                        continue;
                    }
                    Account first = from.id < to.id ? from : to;
                    Account second = first == from ? to : from;
                    first.lock.lock();
                    second.lock.lock();
                    try {
                        long amount = Math.min(from.balance, 1 + rng.below(50));
                        from.balance -= amount;
                        to.balance += amount;
                        from.history.add(new long[] {to.id, -amount});
                        if (from.history.size() > 64) {
                            from.history = new ArrayList<>(from.history.subList(32, from.history.size()));
                        }
                        moved.addAndGet(amount);
                    } finally {
                        second.lock.unlock();
                        first.lock.unlock();
                    }
                }
                done.countDown();
            });
            worker.start();
        }
        done.await();
        long total = 0;
        for (Account a : all) {
            total += a.balance;
        }
        return "bank: " + accounts + " accounts, " + threads + " threads, total " + total
            + (moved.get() > 0 ? ", money moved" : ", nothing moved");
    }
}
