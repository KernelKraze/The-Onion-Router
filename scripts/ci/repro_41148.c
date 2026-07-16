/* Repro for tor#41148 and shutdown lost-wakeup.
 * argv[1] == "idle": let workers drain and go idle before freeing the pool
 * (pure #41148 static-residue path). Default: free while workers are busy
 * (lost-wakeup path). */
#include "orconfig.h"
#include <stdio.h>
#include <string.h>
#include "lib/evloop/workqueue.h"
#include "lib/crypt_ops/crypto_init.h"
#include "lib/log/log.h"
#include "lib/malloc/malloc.h"
#include "lib/time/compat_time.h"

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

int
main(int argc, char **argv)
{
  int idle = (argc > 1 && !strcmp(argv[1], "idle"));
  init_logging(1);
  if (crypto_global_init(0, NULL, NULL) < 0)
    return 2;
  for (int iter = 1; iter <= 50; iter++) {
    replyqueue_t *rq = replyqueue_new(0);
    if (!rq) { printf("iter %d: replyqueue_new failed\n", iter); return 2; }
    threadpool_t *tp = threadpool_new(8, rq, new_state, free_state, NULL);
    if (!tp) { printf("iter %d: threadpool_new failed\n", iter); return 2; }
    for (int i = 0; i < 200; i++)
      threadpool_queue_work(tp, work_fn, reply_fn, NULL);
    if (idle)
      tor_sleep_msec(200);
    threadpool_free(tp);
    printf("iter %d ok\n", iter);
    fflush(stdout);
  }
  printf("ALL DONE\n");
  return 0;
}
