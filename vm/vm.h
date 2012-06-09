#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <stdbool.h>

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"

struct __spt_t
{
  /** The table holding mappings for each address. */
  struct hash pages;

  /**
   * This hash table holds mapped files and associated pages per process,
   * allowing for efficient unmapping.
   */
  struct hash mapped_files;
};

/**
 * Keep our SPT type opaque.
 */
typedef struct __spt_t spt_t;

/**
 * Creates and initializes an SPT.
 * Returns NULL on error.
 */
spt_t *spt_create (void);

/**
 * Destroys an SPT and frees all of its resources.
 */
void spt_destroy (spt_t *s);

/**
 * Creates a new SPT entry and adds it to the SPT.
 * The page is zeroed and write-enabled.
 * Returns false on error.
 */
bool spt_create_entry (void *upage);

/**
 * Loads and returns the page mapped to vaddress in spt.
 * Returns NULL on error.
 */
void *spt_load (spt_t *spt, void *vaddress);

/**
 * Maps a read_bytes long memory area starting at upage.
 * If writable is true, the process can write to the area.
 * If a file is specified, the area will be backed by it.
 * If mapping an actual file fails, all pages previously mapped to
 * this file will be removed, however, if no file is specified and
 * the mapping fails at some point, all pages mapped up to it will
 * remain in the SPT.
 */
bool spt_map_file (struct file *file, off_t ofs, uint8_t *upage,
                   uint32_t read_bytes, bool writable, bool writeback);

/**
 * Removes all mappings for file. (file != NULL)
 */
void spt_unmap_file (struct file *file);

#endif /* vm/vm.h */
