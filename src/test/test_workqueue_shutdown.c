/* Repro for tor#41148 and shutdown lost-wakeup.
 * argv[1] == "idle":   let workers drain and go idle before freeing the
 *                      pool (pure #41148 static-residue path).
 * argv[1] == "update": queue a per-thread update while workers are busy,
 *                      then free immediately, so some update args are
 *                      still pending when threadpool_free_() runs (the
 *                      #41209 update_args cleanup path).
 * Default: free while workers are busy (lost-wakeup path). */
#include "orconfig.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
#include "lib/evloop/workqueue.h"
#include "lib/crypt_ops/crypto_init.h"
#include "lib/log/log.h"
#include "lib/malloc/malloc.h"
#include "lib/time/compat_time.h"

/* Rounds to run. A race that shows up now and then needs repetition, but the
 * idle case sleeps in each round, so the default keeps "make check" quick and
 * CI raises it with TOR_TEST_WORKQUEUE_ROUNDS. */
#define N_ROUNDS_DEFAULT 10

static int
n_rounds(void)
{
  const char *s = getenv("TOR_TEST_WORKQUEUE_ROUNDS");
  if (s) {
    int v = atoi(s);
    if (v > 0)
      return v;
  }
  return N_ROUNDS_DEFAULT;
}

/* A lost wakeup during teardown does not crash, it waits: the pool sits there
 * with nobody left to signal it. Bound the run so that shows up as a failed
 * test rather than as a job that never ends. A round takes milliseconds when
 * the pool tears down properly, so this is generous. */
static void
set_deadline(int rounds)
{
#ifndef _WIN32
  unsigned seconds = (unsigned)(10 + rounds * 2);
  alarm(seconds);
#else
  (void)rounds;
#endif
}

static void *
new_state(void *arg)
{
  (void)arg;
  return tor_malloc_zero(16);
}
static void
free_state(void *st)
{
  tor_free(st);
}
static workqueue_reply_t
work_fn(void *state, void *arg)
{
  (void)state; (void)arg;
  return WQ_RPL_REPLY;
}
static void
reply_fn(void *arg)
{
  (void)arg;
}

/* Update plumbing: a consumed update arg is freed by update_fn (that is
 * the ownership convention); an unconsumed one must be freed by
 * threadpool_free_() through free_update_arg(). Leak checkers verify
 * that both paths fire exactly once per arg. */
static void *
dup_update_arg(void *arg)
{
  (void)arg;
  return tor_malloc_zero(32);
}
static workqueue_reply_t
update_fn(void *state, void *arg)
{
  (void)state;
  tor_free(arg);
  return WQ_RPL_REPLY;
}
static void
free_update_arg(void *arg)
{
  tor_free(arg);
}

int
main(int argc, char **argv)
{
  int idle = (argc > 1 && !strcmp(argv[1], "idle"));
  int update = (argc > 1 && !strcmp(argv[1], "update"));
  init_logging(1);
  if (crypto_global_init(0, NULL, NULL) < 0)
    return 2;
  const int rounds = n_rounds();
  set_deadline(rounds);
  for (int iter = 1; iter <= rounds; iter++) {
    replyqueue_t *rq = replyqueue_new(0);
    if (!rq) { printf("iter %d: replyqueue_new failed\n", iter); return 2; }
    threadpool_t *tp = threadpool_new(8, rq, new_state, free_state, NULL);
    if (!tp) { printf("iter %d: threadpool_new failed\n", iter); return 2; }
    for (int i = 0; i < 200; i++)
      threadpool_queue_work(tp, work_fn, reply_fn, NULL);
    if (update) {
      if (threadpool_queue_update(tp, dup_update_arg, update_fn,
                                  free_update_arg, NULL) < 0) {
        printf("iter %d: queue_update failed\n", iter);
        return 2;
      }
    }
    if (idle)
      tor_sleep_msec(200);
    threadpool_free(tp);
    printf("iter %d ok\n", iter);
    fflush(stdout);
  }
  printf("ALL DONE\n");
  return 0;
}
