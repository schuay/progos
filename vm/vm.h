#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <stdbool.h>

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"

typedef int mapid_t;

struct __spt_t
{
  /** The table holding mappings for each address. */
  struct hash pages;

  /**
   * This hash table holds mapped files and associated pages per process,
   * allowing for efficient unmapping.
   */
  struct hash mapped_files;

  /**
   * The first free map id.
   */
  mapid_t mapid_free;
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
 * The area will be backed by the specified file.
 * If mapping the file fails, all pages previously mapped to
 * this file will be removed.
 * If the mapping is removed via spt_unmap_file() or by killing the
 * process, the given file is closed. Hence it MUST NOT be closed or
 * used anywhere else.
 * Returns an identifier for this mapping, or a negative value on failure.
 */
mapid_t spt_map_file (struct file *file, off_t ofs, uint8_t *upage,
                      uint32_t read_bytes, bool writable, bool writeback);

/**
 * Maps a read_bytes long memory area starting at upage.
 * If writable is true, the process can write to the area.
 * If a file is specified, the area will be backed by it.
 * If the mapping fails, pages which could be mapped correctly are not
 * unmapped. It is expected, that the process is killed if this function
 * fails.
 * Return true if the mapping was created successfully, false on otherwise.
 */
bool spt_map_segment (struct file *file, off_t ofs, void *upage,
                      uint32_t read_bytes, bool writable);

/**
 * Removes all mappings for the given id and closes the backing file.
 */
void spt_unmap_file (mapid_t id);

#endif /* vm/vm.h */
