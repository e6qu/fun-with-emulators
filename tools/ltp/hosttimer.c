/*
 * How late the host's own timers end a sleep, judged as LTP's timer tests
 * judge one (lib/tst_timer_test.c): `hosttimer USEC ITERATIONS THRESHOLD`
 * sleeps USEC microseconds ITERATIONS times on the host timer fwe's waits
 * use (a kqueue EVFILT_TIMER with NOTE_CRITICAL), drops the longest 5%
 * (at least one), and exits 1 if the mean of the rest is more than
 * THRESHOLD microseconds late (LTP's per-sleep threshold), 0 if not.
 * run.py runs it when a timer test fails: a host that misses the same
 * threshold natively cannot be met by a program running on it.
 */
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/event.h>
#include <time.h>
#include <unistd.h>

static long long now_ns(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1000000000LL + t.tv_nsec;
}

static int longest_first(const void *a, const void *b)
{
	long long x = *(const long long *)a, y = *(const long long *)b;
	return x < y ? 1 : x > y ? -1 : 0;
}

int main(int argc, char **argv)
{
	if (argc != 4)
		return 2;
	long long usec = atoll(argv[1]);
	int n = atoi(argv[2]);
	double threshold = atof(argv[3]);
	long long *samples = calloc(n, sizeof(*samples));
	int kq = kqueue();
	if (!samples || kq < 0 || n < 1)
		return 2;
	for (int i = 0; i < n; i++) {
		struct kevent ev, out;
		struct timespec zero = {0, 0};
		long long start = now_ns();
		EV_SET(&ev, 1, EVFILT_TIMER, EV_ADD | EV_ONESHOT,
		       NOTE_NSECONDS | NOTE_CRITICAL, usec * 1000, 0);
		kevent(kq, &ev, 1, NULL, 0, NULL);
		struct pollfd p = {kq, POLLIN, 0};
		poll(&p, 1, -1);
		kevent(kq, NULL, 0, &out, 1, &zero);
		samples[i] = (now_ns() - start) / 1000;
	}
	qsort(samples, n, sizeof(*samples), longest_first);
	int discard = n == 1 ? 0 : (n / 20 > 1 ? n / 20 : 1);
	double sum = 0;
	for (int i = discard; i < n; i++)
		sum += samples[i];
	double mean = sum / (n - discard);
	int late = mean > usec + threshold;
	printf("host: %lldus %d times: max %lldus, trunc mean %.2fus, %s\n", usec, n,
	       samples[0], mean, late ? "late" : "on time");
	return late;
}
