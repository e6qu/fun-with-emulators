/* A minimal dynamically linked program for a libc whose functions assume the
 * full thread-control-block setup that only `__libc_start_main` performs (as
 * glibc's do). It provides its own `_start` and calls a single libc function
 * that is a plain system-call wrapper needing no such setup — `_exit` — so it
 * exercises the dynamic linker (load the interpreter, map the shared libc,
 * resolve one symbol, hand off) without depending on C runtime startup. */

void _exit(int code);

void _start(void) {
    _exit(42);
}
