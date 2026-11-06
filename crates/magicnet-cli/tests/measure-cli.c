/* Measure the executable itself. Forking from Python would include Python's
 * inherited resident-memory high-water mark in wait4's ru_maxrss result. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

static volatile sig_atomic_t child_pid;

static void timed_out(int signal_number) {
    (void)signal_number;
    if (child_pid > 0) kill(child_pid, SIGKILL);
}

int main(int argc, char **argv) {
    if (argc < 2) return 2;
    struct timespec start, end;
    if (clock_gettime(CLOCK_MONOTONIC, &start)) return 2;
    pid_t child = fork();
    if (child < 0) return 2;
    if (child == 0) {
        int sink = open("/dev/null", O_WRONLY);
        if (sink < 0 || dup2(sink, STDOUT_FILENO) < 0) _exit(126);
        close(sink);
        execv(argv[1], argv + 1);
        _exit(127);
    }
    child_pid = child;
    signal(SIGALRM, timed_out);
    alarm(30);
    int status;
    struct rusage usage;
    while (wait4(child, &status, 0, &usage) < 0) {
        if (errno != EINTR) return 2;
    }
    alarm(0);
    child_pid = 0;
    if (clock_gettime(CLOCK_MONOTONIC, &end)) return 2;
    if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) return 1;
    double milliseconds = (end.tv_sec - start.tv_sec) * 1000.0 +
                          (end.tv_nsec - start.tv_nsec) / 1000000.0;
    printf("{\"ms\":%.6f,\"peak_rss_kib\":%ld}\n", milliseconds, usage.ru_maxrss);
    return 0;
}
