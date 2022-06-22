#include "tests/lib.h"
#include "tests/main.h"
#include <pthread.h>
#include <debug.h>
#define COUNT 20

tid_t first;
sema_t execute_1;
/* 
Test cyclic joining.
Should fail because this would deadlock.
*/
void thread_function(void* arg) {
  sema_down(&execute_1);
  tid_t* val = (tid_t*)arg;
  if (pthread_join(*val)) {
    msg("second thread should fail");
  } else {
    msg("first thread can join");
  }
  sema_up(&execute_1);
}

void test_main(void) {
  msg("Main started.");
  sema_check_init(&execute_1, 1);

  sema_down(&execute_1);
  tid_t main_tid = get_tid();
  first = pthread_check_create(thread_function, &main_tid);
  sema_up(&execute_1);

  if (pthread_join(first)) {
    msg("second thread should fail");
  } else {
    msg("first thread can join");
  }
}