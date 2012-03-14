/* Create a large file, and mmap it several times, writing to
   different pages. Then unmaps the file, and reads the data back
   to verify */

#include <string.h>
#include <syscall.h>
#include "tests/vm/sample.inc"
#include "tests/lib.h"
#include "tests/main.h"

/* Offset needs to be larger or equal to page size */
#define OFFSET(i)  (8192*(i))
/* Number of times file is mmapped */
#define N          (8)
/* Size of file */
#define FILE_SIZE  (1024*1024)
/* Address for mmap */
#define ACTUAL(i)  ((void *) (0x10000000 + (i)*FILE_SIZE))


void
test_main (void)
{
  int i;
  int handle;
  mapid_t map[N];
  char buf[1024];
  /* create file */
  CHECK (create ("sample.txt", FILE_SIZE), "create \"sample.txt\"");
  CHECK ((handle = open ("sample.txt")) > 1, "open \"sample.txt\"");
  /* mmap */
  for (i = 0; i < N; i++) {
    CHECK ((map[i] = mmap (handle, ACTUAL(i))) != MAP_FAILED, "mmap \"sample.txt\"");
  }
  /* write */
  for (i = 0; i < N; i++) {
      memcpy (buf, ACTUAL(i)+OFFSET(i+N), 1024); /* not checked */
      memcpy (ACTUAL(i)+OFFSET(i), sample, strlen (sample));
  }
  /* munmap */
  for (i = 0; i < N; i++) {
      munmap (map[i]);
  }
  /* Read back via read(). */
  for (i = 0; i < N; i++) {
      seek (handle, OFFSET(i));
      read (handle, buf, strlen (sample));
      CHECK (!memcmp (buf, sample, strlen (sample)),
             "compare read data against written data");
  }
  close (handle);
}
