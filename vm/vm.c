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
   * The associated file. Note that the SPT is used to close open files
   * on process termination, so memory-mapped files (which must be reopened
   * using file_reopen) must not be used in any other location.
   *
   * Can be NULL if the page has no associated file (i.e., the stack).
   */
  struct file *file;

  /**
   * The associated map id.
   */
  mapid_t mapid;

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

/**
 * Associates a mapped file with its first mapped virtual address.
 * File mappings are always contiguous, which we can exploit for efficient
 * unmapping.
 */
struct mape
{
  struct file *file;
  mapid_t mapid;
  void *vaddress;
  struct hash_elem hash_elem;
};

static bool spt_create_file_entry (struct file *file, mapid_t mapid, off_t ofs,
                                   void *upage, uint32_t read_bytes,
                                   bool writable, bool writeback);
static struct spte *spt_find (spt_t *spt, void *vaddress);
static struct mape *mape_find (struct hash *h, mapid_t id);
static unsigned spte_hash (const struct hash_elem *p, void *aux);
static bool spte_less (const struct hash_elem *a, const struct hash_elem *b,
                       void *aux);
static unsigned file_hash (const struct hash_elem *p, void *aux);
static bool file_less (const struct hash_elem *a, const struct hash_elem *b,
                       void *aux);
static void spte_destroy (struct hash_elem *e, void *aux);
static void mape_destroy (struct hash_elem *e, void *aux);
static bool install_page (void *upage, void *kpage, bool writable);

static bool spt_map (struct file *file, mapid_t mapid, off_t ofs, void *upage,
                     uint32_t read_bytes, bool writable, bool writeback);

spt_t *
spt_create (void)
{
  spt_t *spt = malloc (sizeof (spt_t));
  if (spt == NULL)
    return NULL;

  if (! hash_init (&spt->pages, spte_hash, spte_less, NULL))
    {
      free (spt);
      return NULL;
    }

  if (! hash_init (&spt->mapped_files, file_hash, file_less, NULL))
    {
      hash_destroy (&spt->pages, spte_destroy);
      free (spt);
      return NULL;
    }

  spt->mapid_free = 0;

  return spt;
}

static unsigned
spte_hash (const struct hash_elem *p, void *aux UNUSED)
{
  const struct spte *q = hash_entry (p, struct spte, hash_elem);
  return hash_bytes (&q->vaddress, sizeof (q->vaddress));
}

static bool
spte_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  const struct spte *m = hash_entry (a, struct spte, hash_elem);
  const struct spte *n = hash_entry (b, struct spte, hash_elem);
  return m->vaddress < n->vaddress;
}

static unsigned
file_hash (const struct hash_elem *p, void *aux UNUSED)
{
  const struct mape *q = hash_entry (p, struct mape, hash_elem);
  return hash_bytes (&q->mapid, sizeof (q->mapid));
}

static bool
file_less (const struct hash_elem *a, const struct hash_elem *b,
           void *aux UNUSED)
{
  const struct mape *m = hash_entry (a, struct mape, hash_elem);
  const struct mape *n = hash_entry (b, struct mape, hash_elem);
  return m->mapid < n->mapid;
}

void
spt_destroy (spt_t *spt)
{
  hash_destroy (&spt->pages, spte_destroy);
  hash_destroy (&spt->mapped_files, mape_destroy);
  free (spt);
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

  pagedir_clear_page (t->pagedir, p->vaddress);

  free (p);
}

static void
mape_destroy (struct hash_elem *e, void *aux UNUSED)
{
  struct mape *p = hash_entry (e, struct mape, hash_elem);
  process_lock_filesys ();
  file_close (p->file);
  process_unlock_filesys ();
  free (p);
}

struct spte *
spt_find (spt_t *spt, void *vaddress)
{
  struct spte p;
  struct hash_elem *e;

  p.vaddress = vaddress;
  e = hash_find (&spt->pages, &p.hash_elem);
  if (e == NULL)
    return NULL;
  return hash_entry (e, struct spte, hash_elem);
}

struct mape *
mape_find (struct hash *h, mapid_t id)
{
  struct mape p;
  struct hash_elem *e;

  p.mapid = id;
  e = hash_find (h, &p.hash_elem);
  if (e == NULL)
    return NULL;
  return hash_entry (e, struct mape, hash_elem);
}

bool
spt_create_entry (void *upage, bool writable)
{
  return spt_create_file_entry (NULL, -1, 0, upage, 0, writable, false);
}

static bool
spt_create_file_entry (struct file *file, mapid_t mapid, off_t ofs, void *upage,
                       uint32_t read_bytes, bool writable, bool writeback)
{
  ASSERT (read_bytes <= PGSIZE);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);
  ASSERT (is_user_vaddr (upage));
  ASSERT (!writeback || file != NULL); /* writeback -> (file != NULL) */

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
  spte->mapid = mapid;
  spte->offset = (file == NULL ? 0 : ofs);
  spte->length = (file == NULL ? 0 : read_bytes);
  spte->writeback = (file == NULL ? false : writeback);
  spte->writable = writable;

  /* The address is already mapped. */
  if (hash_insert (&t->spt->pages, &spte->hash_elem) != NULL)
    {
      free (spte);
      return false;
    }

  return true;
}

void
spt_unmap_file (mapid_t id)
{
  struct thread *t = thread_current();

  struct mape *mape = mape_find (&t->spt->mapped_files, id);
  if (mape == NULL)
    return;

  void *vaddr;
  for (vaddr = mape->vaddress; ; vaddr += PGSIZE)
    {
      struct spte *p = spt_find (t->spt, vaddr);

      /* If the page has a different map id, we're done. */
      if (p == NULL || p->mapid != id)
        break;

      /* Otherwise, unmap this page. */
      hash_delete (&t->spt->pages, &p->hash_elem);
      spte_destroy (&p->hash_elem, NULL);
    }

  if (id < t->spt->mapid_free)
    t->spt->mapid_free = id;

  hash_delete (&t->spt->mapped_files, &mape->hash_elem);
  mape_destroy (&mape->hash_elem, NULL);
}

bool
spt_map_segment (struct file *file, off_t ofs, void *upage, uint32_t read_bytes,
                 bool writable)
{
  return spt_map (file, -1, ofs, upage, read_bytes, writable, false);
}

static bool
spt_map (struct file *file, mapid_t mapid, off_t ofs, void *upage,
         uint32_t read_bytes, bool writable, bool writeback)
{
  ASSERT (ofs % PGSIZE == 0);

  /* Fail if size is 0 or an attempt to map to 0x0 is made. */
  if (read_bytes == 0 || upage == 0)
    return false;

  /* Prevent mapping in kernel space. */
  if (! is_user_vaddr (upage))
    return false;

  /* Check this explicitly, so the mmap handler doesn't have to. */
  if (pg_ofs (upage) != 0)
    return false;

  /* Map the file. */
  while (read_bytes > 0)
    {
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;

      /* Add mapping to supplemental page table. */
      if (! spt_create_file_entry (file, mapid, ofs, upage, page_read_bytes,
                                   writable, writeback))
        {
          return false;
        }

      read_bytes -= page_read_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }

  return true;
}

mapid_t
spt_map_file (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, bool writable, bool writeback)
{
  ASSERT (file != NULL);
  ASSERT (ofs % PGSIZE == 0);

  /* Obtain the next available map id, save our mapping, and update the next
   * free id. */
  struct mape *mape = malloc (sizeof (struct mape));
  if (mape == NULL)
    return -1;

  struct thread *t = thread_current ();
  mapid_t id = t->spt->mapid_free;

  mape->file = file;
  mape->mapid = id;
  mape->vaddress = upage;

  if (hash_insert (&t->spt->mapped_files, &mape->hash_elem) != NULL)
    {
      free (mape);
      return -1;
    }

  do
    t->spt->mapid_free++;
  while (mape_find (&t->spt->mapped_files, t->spt->mapid_free) != NULL);

  if (! spt_map (file, id, ofs, upage, read_bytes, writable, writeback))
    {
      spt_unmap_file (id);
      return -1;;
    }

  return id;
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
      bool has_lock = process_has_filesys_lock ();

      if (! has_lock)
        {
          process_lock_filesys ();
        }

      file_seek (spte->file, spte->offset);
      int read_bytes = file_read (spte->file, kpage, spte->length);

      if (! has_lock)
        {
          process_unlock_filesys ();
        }

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
