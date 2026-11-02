/* A minimal dynamically linked program.
 *
 * It provides its own `_start` and calls two libc functions (`write` and
 * `_exit`) that the dynamic linker must resolve from the shared libc at load
 * time. No C runtime startup objects are involved, so this isolates the
 * dynamic linker itself: it must map and self-relocate `ld-musl`, apply this
 * program's `R_AARCH64_JUMP_SLOT` relocations against libc, set up the thread
 * pointer, and transfer control here. */

long write(int fd, const void *buf, unsigned long len);
void _exit(int code);

void _start(void) {
    static const char msg[] = "dynamic-min: hello from musl\n";
    write(1, msg, sizeof(msg) - 1);
    _exit(0);
}
