/* Tests the tell and seek syscalls. */

#include <syscall.h>
#include "tests/lib.h"
#include "tests/main.h"

void test_main(void) {
  int handle = open("sample.txt");
  unsigned loc = tell(handle);
  if (loc != 0)
    fail("tell() returned %d", loc);
}
