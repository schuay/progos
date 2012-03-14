/* Test the limit for (1) number of arguments and (2) total size of arguments */
#include <syscall.h>
#include <string.h>
#include "tests/lib.h"

#define MAX_SIZE 4096

static bool recurse (int, int);

char cmd[MAX_SIZE * 4];

static bool
recurse (int argsize, int argcount)
{
  int i, j;
  char *p;
  strlcpy (cmd, "args-limit", 11);
  p = cmd+strlen(cmd);
  for (i = 0; i < argcount; i++) {
    *p++ = ' ';
    for (j = 0; j < argsize; j++) {
      *p++ = 'X';
    }
  }
  *p = 0;
  if (wait (exec (cmd)) < 0) {
    return false;
  } else {
    return true;
  }
}

int
main (int argc, char **argv)
{
  test_name = argv[0];
  if(argc <= 1) {
    int step;
    int max_args = 0, max_size = 0;

    msg ("begin");

    /* Binary search number of arguments */
    for (step = MAX_SIZE; step > 0 && max_args < MAX_SIZE; step>>=1) {
      int t = max_args + step;
      if (recurse (1, t)) {
	max_args = t;
      }
    }
    if (max_args > 63) {
      msg ("success. at least 64 command line arguments are supported.");
    } else {
      msg ("FAIL: Only %d command line arguments are supported",max_args);
    }
    /* Binary search size of arguments */
    for (step = MAX_SIZE; step > 0 && max_size < MAX_SIZE; step>>=1) {
      int t = max_size + step;
      if (recurse (t, 1)) {
	max_size = t;
      }
    }
    if (max_size >= 100) {
      msg ("success. arguments with at least 100 bytes are supported.");
    } else {
      msg ("FAIL: Arguments with more than %d bytes are not supported.",max_size);
    }
    msg ("end");
  }
  return 0;
}
