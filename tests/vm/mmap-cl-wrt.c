#include <string.h>
#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

#define ACTUAL ((void *) 0x10000000)

char sample_contents[sizeof sample];

void
test_main (void)
{
  int handle;
  int mapid;

  CHECK (create ("dummy.txt", sizeof sample), "create \"dummy.txt\"");
  CHECK (create ("sample.txt", sizeof sample), "create \"sample.txt\"");

  CHECK ( (handle = open ("dummy.txt")) > 1, "open \"dummy.txt\"");
  CHECK ( (mapid = mmap (handle, ACTUAL)) != MAP_FAILED, "mmap \"dummy.txt\"");
  memcpy (ACTUAL, sample, sizeof sample);

  for (handle = 2; handle < 1024; handle++)
    {
      close (handle);
    }

  CHECK ( (handle = open ("sample.txt")) > 1, "open \"sample.txt\"");

  munmap (mapid);

  /* Check file contents. */
  check_file ("sample.txt", sample_contents, sizeof sample);
}
