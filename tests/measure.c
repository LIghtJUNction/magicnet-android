/* Host measurement helper: avoid attributing the Python parent's fork image
 * to the measured CLI's peak RSS. This file is not shipped in the module. */
#define _GNU_SOURCE
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>

static pid_t measured;
static void deadline(int ignored) { (void)ignored; if (measured > 0) kill(measured, SIGKILL); }
int main(int argc, char **argv) {
  if (argc < 2) return 64;
  struct timespec before, after;
  clock_gettime(CLOCK_MONOTONIC, &before);
  measured = fork();
  if (measured < 0) return 71;
  if (measured == 0) { execv(argv[1], argv + 1); _exit(127); }
  signal(SIGALRM, deadline);
  alarm(15);
  int status = 0;
  struct rusage usage;
  while (wait4(measured, &status, 0, &usage) < 0) if (errno != EINTR) return 71;
  measured = 0;
  alarm(0);
  clock_gettime(CLOCK_MONOTONIC, &after);
  double ms = (after.tv_sec - before.tv_sec) * 1000.0 + (after.tv_nsec - before.tv_nsec) / 1000000.0;
  fprintf(stderr, "{\"rss_kib\":%ld,\"child_wall_ms\":%.6f}\n", usage.ru_maxrss, ms);
  if (WIFEXITED(status)) return WEXITSTATUS(status);
  if (WIFSIGNALED(status)) return 128 + WTERMSIG(status);
  return 70;
}
