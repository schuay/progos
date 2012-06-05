#include "vm.h"

#include "debug.h"
#include "lib/string.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "userprog/pagedir.h"

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

struct spte *
spte_create (struct file *file, off_t ofs, void *upage,
    uint32_t read_bytes, bool writable)
{
  ASSERT (read_bytes <= PGSIZE);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  struct thread *t = thread_current ();

  struct spte *spte = malloc (sizeof (struct spte));
  if (spte == NULL)
    return NULL;

  spte->vaddress = upage;
  spte->file = file;
  spte->offset = (file == NULL ? 0 : ofs);
  spte->length = (file == NULL ? 0 : read_bytes);
  spte->writable = writable;

  hash_insert (t->spt, &spte->hash_elem);

  return spte;
}

bool
spte_load (const struct spte *spte)
{
  ASSERT (spte != NULL);


  /* Get a page of memory. */
  uint8_t *kpage = palloc_get_page (PAL_USER);
  if (kpage == NULL)
    return false;

  /* Load this page. */
  if (spte->file != NULL)
    {
      file_seek (spte->file, spte->offset);
      if (file_read (spte->file, kpage, spte->length) != (int) spte->length)
        {
          palloc_free_page (kpage);
          return false;
        }
    }

  /* Zero the rest of the page. */
  memset (kpage + spte->length, 0, PGSIZE - spte->length);

  /* Add the page to the process's address space. */
  if (!install_page (spte->vaddress, kpage, spte->writable))
    {
      palloc_free_page (kpage);
      return false;
    }

  return true;
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
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
      && pagedir_set_page (t->pagedir, upage, kpage, writable));
}
