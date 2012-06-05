#include "vm.h"
#include "debug.h"
#include "threads/malloc.h"

static unsigned spt_hash (const struct hash_elem *p, void *aux);
static bool spt_less (const struct hash_elem *a, const struct hash_elem *b,
                      void *aux);
static void spte_destroy (struct hash_elem *e, void *aux);

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
