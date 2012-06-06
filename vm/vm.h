#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <stdbool.h>

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"

/**
 * Keep our SPT type opaque.
 * Right now, our implementation uses a hash table.
 */
typedef struct hash spt_t;

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
 * Returns false on error.
 */
bool spt_create_entry (struct file *file, off_t ofs, void *upage,
                       uint32_t read_bytes, bool writable);

/**
 * Loads the page mapped to vaddress in spt.
 * Returns false on error.
 */
bool spt_load (spt_t *spt, void *vaddress);

#endif /* vm/vm.h */
