/* Calls both ends of a library whose code is longer than a branch reaches
 * (guests/asm/bigcode.S); exits 0 if both read the same thread pointer. */
unsigned long first(void);
unsigned long last(void);

int main(void) {
    unsigned long a = first(), b = last();
    return a != 0 && a == b ? 0 : 1;
}
