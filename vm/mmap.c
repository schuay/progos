#include "vm/mmap.h"

#include "debug.h"

mapid_t mmap (int fd UNUSED, void *addr UNUSED)
{
  /* TODO
   * Reopen the file; check for mapping collisions; map the file; add it to the
   * list of this thread's open files and keep track of the mapped addresses so
   * we can munmap it later. Read section 4.3.4 *carefully* when implementing
   * this section. */

  return 2;
}

void munmap (mapid_t mapping UNUSED)
{
  /* TODO
   * Unmap the pages associated with id. Close the associated file and remove it
   * from the list of open files. Read section 4.3.4 *carefully* when
   * implementing this section. */
}
