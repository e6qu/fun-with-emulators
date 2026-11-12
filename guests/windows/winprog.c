/* A Windows console program for ARM64, run through Wine under fwe: files,
 * threads, an exception taken by a handler, and a child process.
 *
 * Built by the tests with `zig cc -target aarch64-windows-gnu` (mingw-w64's
 * headers and libraries, which zig carries). Each line it prints is checked.
 */
#include <stdio.h>
#include <string.h>
#include <windows.h>

static volatile LONG counter;

static DWORD WINAPI worker(LPVOID arg) {
    for (int i = 0; i < 1000; i++) {
        InterlockedIncrement(&counter);
    }
    return (DWORD)(ULONG_PTR)arg;
}

static LONG WINAPI on_exception(EXCEPTION_POINTERS *info) {
    if (info->ExceptionRecord->ExceptionCode == 0xE0000001) {
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    return EXCEPTION_CONTINUE_SEARCH;
}

int main(int argc, char **argv) {
    if (argc > 1 && strcmp(argv[1], "child") == 0) {
        printf("child: %s\n", argc > 2 ? argv[2] : "");
        fflush(stdout);
        return 7;
    }
    SYSTEM_INFO si;
    GetNativeSystemInfo(&si);
    printf("arm64: %d\n", si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_ARM64);

    /* A file written, read back and deleted. */
    const char *name = "winprog-test.txt";
    HANDLE f = CreateFileA(name, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, 0, NULL);
    DWORD done = 0;
    WriteFile(f, "written by Windows", 18, &done, NULL);
    CloseHandle(f);
    char buf[64] = {0};
    f = CreateFileA(name, GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
    ReadFile(f, buf, sizeof buf - 1, &done, NULL);
    CloseHandle(f);
    printf("file: %s, deleted %d\n", buf, DeleteFileA(name) != 0);

    /* Threads, joined, with their exit codes. */
    HANDLE t[4];
    for (int i = 0; i < 4; i++) {
        t[i] = CreateThread(NULL, 0, worker, (LPVOID)(ULONG_PTR)(i + 1), 0, NULL);
    }
    WaitForMultipleObjects(4, t, TRUE, INFINITE);
    DWORD sum = 0;
    for (int i = 0; i < 4; i++) {
        DWORD code = 0;
        GetExitCodeThread(t[i], &code);
        sum += code;
        CloseHandle(t[i]);
    }
    printf("threads: %ld, exit codes %lu\n", (long)counter, (unsigned long)sum);

    /* An exception raised and continued by a vectored handler. */
    PVOID h = AddVectoredExceptionHandler(1, on_exception);
    RaiseException(0xE0000001, 0, 0, NULL);
    RemoveVectoredExceptionHandler(h);
    printf("exception: handled\n");

    /* This program again as a child process, its exit code collected. */
    char self[MAX_PATH];
    GetModuleFileNameA(NULL, self, MAX_PATH);
    char cmd[MAX_PATH + 32];
    snprintf(cmd, sizeof cmd, "\"%s\" child hello", self);
    STARTUPINFOA start = {sizeof start};
    PROCESS_INFORMATION proc;
    fflush(stdout);
    if (!CreateProcessA(NULL, cmd, NULL, NULL, TRUE, 0, NULL, NULL, &start, &proc)) {
        printf("CreateProcess failed: %lu\n", (unsigned long)GetLastError());
        return 1;
    }
    WaitForSingleObject(proc.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(proc.hProcess, &code);
    CloseHandle(proc.hThread);
    CloseHandle(proc.hProcess);
    printf("child exited %lu\n", (unsigned long)code);
    return 0;
}
