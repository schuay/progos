#ifndef VM_H
#define VM_H

#include <stdint.h>
#include <stdbool.h>

typedef struct hash spt_t;

#include "filesys/file.h"
#include "filesys/off_t.h"
#include "lib/kernel/hash.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

spt_t *spt_create (void);
void spt_destroy (spt_t *s);

/**
 * Creates a new SPT entry and adds it to the SPT.
 * Returns NULL on error.
 */
struct spte *spte_create (struct file *file, off_t ofs, void *upage,
    uint32_t read_bytes, bool writable);

/**
 * Loads the page described by spte.
 */
bool spte_load (const struct spte *spte);

/**
 * An entry of the supplemental page table (SPT).
 *
 * Exactly one SPT exists per process. It stores all memory areas which contain
 * user-accessable data, namely the stack, the executable loadable segments,
 * and memory-mapped files. There is no dynamic memory allocation on the heap.
 *
 * The SPT could be implemented by creating a hash table of SPTE with the user
 * virtual address as the key.
 */
struct spte {
    /**
     * The user virtual address this page is mapped to.
     */
    void *vaddress;

    /**
     * The associated file. Note that the SPT is not used to close open files
     * on process termination, so memory-mapped files (which should be reopened
     * using file_reopen) need to be tracked in some other fashion.
     *
     * Can be NULL if the page has no associated file (i.e., the stack).
     */
    struct file *file;

    /**
     * The starting offset within file. Ignored if file is NULL.
     * 0 <= offset < filesize. offset % PGSIZE == 0.
     */
    off_t offset;

    /**
     * The length of the desired mapping. This is usually equal to PGSIZE, unless
     * we are at EOF. The rest of the page is zeroed. Ignored if file is NULL.
     * 0 <= length < PGSIZE. offset + length < filesize.
     */
    uint32_t length;

    /**
     * If writable is true, the page is marked read/write. Otherwise, it is
     * read-only.
     */
    bool writable;

    /**
     * The hash table element.
     */
    struct hash_elem hash_elem;
};

#endif /* vm/vm.h */
