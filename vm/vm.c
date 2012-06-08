#include "vm.h"

#include "debug.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

/**
 * An entry of the supplemental page table (SPT).
 *
 * Exactly one SPT exists per process. It stores all memory areas which contain
 * user-accessible data, namely the stack, the executable loadable segments,
 * and memory-mapped files. There is no dynamic memory allocation on the heap.
 *
 * The SPT could be implemented by creating a hash table of SPTE with the user
 * virtual address as the key.
 */
struct spte
{
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
   * If writeback is true, the page is written back to the file when
   * the page is unmapped (which could occur either by exiting or killing
   * the process or by calling munmap). Ignored if file is NULL.
   */
  bool writeback;

  /**
   * The hash table element.
   */
  struct hash_elem hash_elem;
};

static struct spte *spt_find (spt_t *spt, void *vaddress);
static unsigned spt_hash (const struct hash_elem *p, void *aux);
static bool spt_less (const struct hash_elem *a, const struct hash_elem *b,
                      void *aux);
static void spte_destroy (struct hash_elem *e, void *aux);
static bool install_page (void *upage, void *kpage, bool writable);

spt_t *
spt_create (void)
{
  spt_t *spt = malloc (sizeof (spt_t));
  ASSERT (hash_init (spt, spt_hash, spt_less, NULL));
  return spt;
}

static unsigned
spt_hash (const struct hash_elem *p, void *aux UNUSED)
{
  const struct spte *q = hash_entry (p, struct spte, hash_elem);
  return hash_bytes (&q->vaddress, sizeof (q->vaddress));
}

static bool
spt_less (const struct hash_elem *a, const struct hash_elem *b,
          void *aux UNUSED)
{
  const struct spte *m = hash_entry (a, struct spte, hash_elem);
  const struct spte *n = hash_entry (b, struct spte, hash_elem);
  return m->vaddress < n->vaddress;
}

void
spt_destroy (spt_t *spt)
{
  hash_destroy (spt, spte_destroy);
}

static void
spte_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct spte *p = hash_entry (e, struct spte, hash_elem);

  struct thread *t = thread_current();
  if (p->writeback && pagedir_is_dirty (t->pagedir, p->vaddress))
    {
      process_lock_filesys ();

      file_seek (p->file, p->offset);
      (void) file_write (p->file, p->vaddress, p->length);

      process_unlock_filesys ();
    }

  free (p);
}

struct spte *
spt_find (spt_t *spt, void *vaddress)
{
  struct spte p;
  struct hash_elem *e;

  p.vaddress = vaddress;
  e = hash_find (spt, &p.hash_elem);
  if (e == NULL)
    return NULL;
  return hash_entry (e, struct spte, hash_elem);
}

bool
spt_create_entry (struct file *file, off_t ofs, void *upage,
                  uint32_t read_bytes, bool writable, bool writeback)
{
  ASSERT (read_bytes <= PGSIZE);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (!writeback || file != NULL) /* writeback -> (file != NULL) */

  struct thread *t = thread_current();

  /* TODO: This could use some optimization. Ideally, these entries should be
   * in a contiguous area of memory. Since creation and removal is handled
   * within this file, that should not be a problem. Also, it would allow us to
   * remove the malloc dependency. */
  struct spte *spte = malloc (sizeof (struct spte));
  if (spte == NULL)
    return false;

  spte->vaddress = upage;
  spte->file = file;
  spte->offset = (file == NULL ? 0 : ofs);
  spte->length = (file == NULL ? 0 : read_bytes);
  spte->writeback = (file == NULL ? false : writeback);
  spte->writable = writable;

  /* The address is already mapped. */
  if (hash_insert (t->spt, &spte->hash_elem) != NULL)
    {
      free (spte);
      return false;
    }

  return true;
}

void
spt_unmap_file (struct file *file)
{
  ASSERT (file != NULL);

  struct thread *t = thread_current();

  /* FIXME: this is _very_ inefficient */
  struct hash_iterator i;
  hash_first (&i, t->spt);
  while (hash_next (&i))
    {
      struct hash_elem *e = hash_cur (&i);
      struct spte *p = hash_entry (e, struct spte, hash_elem);

      if (p->file == file)
        {
          hash_delete (t->spt, e);
          spte_destroy (e, NULL);
          hash_first (&i, t->spt);
        }
    }
}

bool
spt_map_file (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, bool writable, bool writeback)
{
  ASSERT (ofs % PGSIZE == 0);

  /* Prevent mapping in kernel space. */
  if (! is_user_vaddr (upage))
    {
      return false;
    }

  /* Check this explicitly, so the mmap handler doesn't have to. */
  if (pg_ofs (upage) != 0)
    {
      return false;
    }

  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;

      /* Add mapping to supplemental page table. */
      if (! spt_create_entry (file, ofs, upage, page_read_bytes,
                              writable, writeback))
        {
          /* If we tried to map a file previously, we have to unmap all
             of its previously mapped pages. If something else failed,
             we assume that the process will exit (and thus unmap all
             pages) anyway. */
          /* FIXME: mapping one's own executable and failing will result in the
             text and data being unmapped. */
          if (file != NULL)
            {
              spt_unmap_file (file);
            }
          return false;
        }

      read_bytes -= page_read_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }

  return true;
}

void *
spt_load (spt_t *spt, void *vaddress)
{
  /* Retrieve the page table entry. */
  struct spte *spte = spt_find (spt, vaddress);
  if (spte == NULL)
    return NULL;

  /* Get a page of memory. */
  uint8_t *kpage = palloc_get_page (PAL_USER);
  if (kpage == NULL)
    return NULL;

  /* Load this page. */
  if (spte->file != NULL)
    {
      process_lock_filesys ();

      file_seek (spte->file, spte->offset);
      int read_bytes = file_read (spte->file, kpage, spte->length);

      process_unlock_filesys ();

      if (read_bytes != (int) spte->length)
        {
          palloc_free_page (kpage);
          return NULL;
        }
    }

  /* Zero the rest of the page. */
  memset (kpage + spte->length, 0, PGSIZE - spte->length);

  /* Add the page to the process's address space. */
  if (!install_page (spte->vaddress, kpage, spte->writable))
    {
      palloc_free_page (kpage);
      return NULL;
    }

  return kpage;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
