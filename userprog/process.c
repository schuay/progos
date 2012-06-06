#include "userprog/process.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

/* data structure to communicate with the thread initializing a new process */
struct start_aux_data
{
  char *filename;
  char **argv;
  int argc;
  struct semaphore startup_sem;
  struct thread *parent_thread;
  struct process *new_process;
};

/* filesystem lock */
struct lock filesys_lock;

/* prototypes */
static thread_func start_process NO_RETURN;
static bool load (struct start_aux_data *aux, void (**eip) (void), void **esp);
static bool setup_stack (struct start_aux_data *aux, void **esp);
static bool init_fd_table (struct fd_table *table);

/* Initialize the filesystem lock */
void
process_init ()
{
  lock_init (&filesys_lock);
}

/* Get current process (only valid for processes) */
struct process *
process_current ()
{
  ASSERT (thread_current()->process != NULL);
  return thread_current()->process;
}

/* Splits the command line in BUF into filename and arguments and
   stores filename, argc and argv in AUX. The argv array is stored
   at BUF + LEN, where LEN is the length of the string in buf. It
   is assumed that buf points to an entire page which can be
   modified at will. */
static bool
process_parse_args (char *buf, size_t len, struct start_aux_data *aux)
{
  int argc = 0;
  char **argv_ptr;
  char *arg, *save_ptr;

  argv_ptr = (char **) (buf + len);
  aux->argv = argv_ptr;
  for (arg = strtok_r (buf, " ", &save_ptr); arg != NULL;
       arg = strtok_r (NULL, " ", &save_ptr), argv_ptr++, argc++)
    {
      /* Not enough space for argv on the page. */
      if (argv_ptr >= (char **) (buf + PGSIZE - sizeof (arg)))
        {
          return false;
        }
      *argv_ptr = arg;
    }
  *argv_ptr = NULL;
  aux->argc = argc;

  aux->filename = buf;

  return true;
}

/* Starts a new thread running a user program loaded from
   `filename`.
   The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   thread id, or TID_ERROR if the thread cannot be created.

   CMD is parsed using process_parse_args and the arguments are
   passed on to the new process. */
tid_t
process_execute (const char *cmd)
{
  size_t len;
  tid_t tid = TID_ERROR;
  char *cmd_copy = NULL;
  struct start_aux_data *aux_data = NULL;

  /* Setup the auxiliary data for starting up the new process */
  cmd_copy = palloc_get_page (0);
  aux_data = palloc_get_page (0);
  if (aux_data == NULL || cmd_copy == NULL)
    goto done;

  /* Split cmd into args and store them in aux_data->argv. */
  len = strlcpy (cmd_copy, cmd, PGSIZE);
  if (! process_parse_args (cmd_copy, len, aux_data))
    {
      goto done;
    }

  aux_data->parent_thread = thread_current ();
  aux_data->new_process = NULL;
  sema_init (&aux_data->startup_sem, 0);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create (cmd_copy, PRI_DEFAULT, start_process, aux_data);
  if (tid == TID_ERROR)
    goto done;

  /* wait for startup */
  sema_down (&aux_data->startup_sem);
  if (aux_data->new_process == NULL)
    {
      tid = TID_ERROR;
      goto done;
    }
  /* register child process */
  list_push_back (&thread_current()->children,
                  &aux_data->new_process->parentelem);

done:
  palloc_free_page (cmd_copy);
  palloc_free_page (aux_data);
  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void
start_process (void *aux)
{
  struct intr_frame if_;
  struct start_aux_data *aux_data = (struct start_aux_data *) aux;
  struct thread *thread = thread_current ();

  /* Initialize Process */
  struct process *process = palloc_get_page (PAL_ZERO);
  if (process == NULL)
    goto signal;
  sema_init (&process->exit_sem, 0);
  lock_init (&process->exit_lock);
  process->exit_status = -1;
  if (! init_fd_table (&process->fd_table))
    goto signal;

  /* register process */
  process->thread_id  = thread->tid;
  process->parent_tid = aux_data->parent_thread->tid;
  thread->process = process;

  /* Initialize interrupt frame and load executable. */
  memset (&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if (! load (aux_data, &if_.eip, &if_.esp))
    {
      thread->process = NULL;
    }
  else
    {
      aux_data->new_process = thread->process;
    }

signal:
  /* Signal the parent process that loading is finished */
  sema_up (&aux_data->startup_sem); /* transfer ownership of aux_data */

  /* If process startup failed, quit. */
  if (thread->process == NULL)
    {
      if (process != NULL)
        {
          if (process->fd_table.fds != NULL)
            palloc_free_page (process->fd_table.fds);
          palloc_free_page (process);
        }
      thread_exit ();
    }

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile ("movl %0, %%esp; jmp intr_exit" : : "g" (&if_) : "memory");
  NOT_REACHED ();
}

/* Waits for thread TID to die and returns its exit status.  If
   it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If TID is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given TID, returns -1
   immediately, without waiting. */
int
process_wait (tid_t child_tid)
{
  struct thread *cur = thread_current ();
  struct process *child = NULL;

  /* iterate over child processes */
  struct list_elem *e = list_head (&cur->children);
  while ( (e = list_next (e)) != list_end (&cur->children))
    {
      struct process *t = list_entry (e, struct process, parentelem);
      if (t->thread_id == child_tid)
        {
          list_remove (e);
          child = t;
          break;
        }
    }
  if (child == NULL)
    {
      return -1;
    }
  sema_down (&child->exit_sem);
  int exit_status = child->exit_status;
  palloc_free_page (child);
  return exit_status;
}

/* Free the current process's resources. */
void
process_exit (void)
{
  struct thread *thread = thread_current ();
  ASSERT (thread != NULL);

  /* remove (and if necessary clean up) child processes */
  struct list_elem *e = list_head (&thread->children);
  while ( (e = list_next (e)) != list_end (&thread->children))
    {
      struct process *p = list_entry (e, struct process, parentelem);
      bool process_dying;
      lock_acquire (&p->exit_lock);
      process_dying = p->parent_tid < 0;
      p->parent_tid = -1;
      lock_release (&p->exit_lock);
      if (process_dying)
        palloc_free_page (p);
    }

  if (thread->process == NULL)
    return; /* not a process, nothing else left to do */

  struct process *proc = thread->process;
  uint32_t *pd;

  printf ("%s: exit(%d)\n", thread->name, proc->exit_status);

  /* close executable, allow write */
  if (proc->executable != NULL)
    {
      lock_acquire (&filesys_lock);
      file_close (proc->executable);
      lock_release (&filesys_lock);
    }

  int fd;
  for (fd = 2; fd <= proc->fd_table.fd_max; fd++)
    {
      process_close_file (fd);
    }
  palloc_free_page (proc->fd_table.fds);

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = thread->pagedir;
  if (pd != NULL)
    {
      /* Correct ordering here is crucial.  We must set
           cur->pagedir to NULL before switching page directories,
           so that a timer interrupt can't switch back to the
           process page directory.  We must activate the base page
           directory before destroying the process's page
           directory, or our active page directory will be one
           that's been freed (and cleared). */
      thread->pagedir = NULL;
      pagedir_activate (NULL);
      pagedir_destroy (pd);
    }

  /* Destroy the process structure if the parent is not alive
   * any more. Atomic test and set would be sufficient here.
   */
  bool parent_dead = false;
  lock_acquire (&proc->exit_lock);
  parent_dead = proc->parent_tid < 0;
  proc->parent_tid = -1;
  lock_release (&proc->exit_lock);
  if (parent_dead)
    {
      palloc_free_page (proc);
    }
  else
    {
      sema_up (&proc->exit_sem);
    }
}

/* Sets up the CPU for running user code in the current
   thread.
   This function is called on every context switch. */
void
process_activate (void)
{
  struct thread *t = thread_current ();
  /* Activate thread's page tables. */
  pagedir_activate (t->pagedir);

  /* Set thread's kernel stack for use in processing
     interrupts. */
  tss_update ();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32   /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32   /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32   /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16   /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr
{
  unsigned char e_ident[16];
  Elf32_Half    e_type;
  Elf32_Half    e_machine;
  Elf32_Word    e_version;
  Elf32_Addr    e_entry;
  Elf32_Off     e_phoff;
  Elf32_Off     e_shoff;
  Elf32_Word    e_flags;
  Elf32_Half    e_ehsize;
  Elf32_Half    e_phentsize;
  Elf32_Half    e_phnum;
  Elf32_Half    e_shentsize;
  Elf32_Half    e_shnum;
  Elf32_Half    e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr
{
  Elf32_Word p_type;
  Elf32_Off  p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL    0            /* Ignore. */
#define PT_LOAD    1            /* Loadable segment. */
#define PT_DYNAMIC 2            /* Dynamic linking info. */
#define PT_INTERP  3            /* Name of dynamic loader. */
#define PT_NOTE    4            /* Auxiliary info. */
#define PT_SHLIB   5            /* Reserved. */
#define PT_PHDR    6            /* Program header table. */
#define PT_STACK   0x6474e551   /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1          /* Executable. */
#define PF_W 2          /* Writable. */
#define PF_R 4          /* Readable. */

static bool validate_segment (const struct Elf32_Phdr *, struct file *);
static bool load_segment (struct file *file, off_t ofs, uint8_t *upage,
                          uint32_t read_bytes, uint32_t zero_bytes,
                          bool writable);

/* Loads an ELF executable from AUX->filename (the first word of
   cmd) into the current thread. The AUX->argv and argc are stored
   on the new thread's stack (using setup_stack).
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool
load (struct start_aux_data *aux, void (**eip) (void), void **esp)
{
  struct thread *t = thread_current ();
  struct Elf32_Ehdr ehdr;
  struct file *file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pagedir = pagedir_create ();
  if (t->pagedir == NULL)
    return false;
  process_activate ();

  /* Allocate supplemental page table. */
  t->spt = spt_create ();

  /* Coarse grained filesystem lock for loading */
  lock_acquire (&filesys_lock);

  /* Open executable file. */
  file = filesys_open (aux->filename);
  if (file == NULL)
    goto done;

  /* Deny writes to the file during loading */
  file_deny_write (file);

  /* Read and verify executable header. */
  if (file_read (file, &ehdr, sizeof ehdr) != sizeof ehdr
      || memcmp (ehdr.e_ident, "\177ELF\1\1\1", 7)
      || ehdr.e_type != 2
      || ehdr.e_machine != 3
      || ehdr.e_version != 1
      || ehdr.e_phentsize != sizeof (struct Elf32_Phdr)
      || ehdr.e_phnum > 1024)
    {
      printf ("load: %s: error loading executable\n", aux->filename);
      goto done;
    }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++)
    {
      struct Elf32_Phdr phdr;

      if (file_ofs < 0 || file_ofs > file_length (file))
        goto done;
      file_seek (file, file_ofs);

      if (file_read (file, &phdr, sizeof phdr) != sizeof phdr)
        goto done;
      file_ofs += sizeof phdr;
      if (phdr.p_vaddr < PGSIZE)
        continue; /* Ignore build-id segment */
      switch (phdr.p_type)
        {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
          /* Ignore this segment. */
          break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
          goto done;
        case PT_LOAD:
          if (phdr.p_vaddr == 0)
            break; // Ignore the .note.gnu.build-i segment
          if (validate_segment (&phdr, file))
            {
              bool writable = (phdr.p_flags & PF_W) != 0;
              uint32_t file_page = phdr.p_offset & ~PGMASK;
              uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
              uint32_t page_offset = phdr.p_vaddr & PGMASK;
              uint32_t read_bytes, zero_bytes;
              if (phdr.p_filesz > 0)
                {
                  /* Normal segment.
                             Read initial part from disk and zero the rest. */
                  read_bytes = page_offset + phdr.p_filesz;
                  zero_bytes = (ROUND_UP (page_offset + phdr.p_memsz, PGSIZE)
                                - read_bytes);
                }
              else
                {
                  /* Entirely zero.
                             Don't read anything from disk. */
                  read_bytes = 0;
                  zero_bytes = ROUND_UP (page_offset + phdr.p_memsz, PGSIZE);
                }
              if (!load_segment (file, file_page, (void *) mem_page,
                                 read_bytes, zero_bytes, writable))
                goto done;
            }
          else
            goto done;
          break;
        }
    }

  /* Set up stack. */
  if (!setup_stack (aux, esp))
    goto done;

  /* Start address. */
  *eip = (void ( *) (void)) ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  if (success)
    {
      process_current()->executable = file;
    }
  else
    {
      file_close (file);
    }
  lock_release (&filesys_lock);
  return success;
}

/* load() helpers. */

static bool install_page (void *upage, void *kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool
validate_segment (const struct Elf32_Phdr *phdr, struct file *file)
{
  /* p_offset and p_vaddr must have the same page offset. */
  if ( (phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off) file_length (file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr ( (void *) phdr->p_vaddr))
    return false;
  if (!is_user_vaddr ( (void *) (phdr->p_vaddr + phdr->p_memsz)))
    return false;

  /* The region cannot "wrap around" across the kernel virtual
     address space. */
  if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
    return false;

  /* Disallow mapping page 0.
     Not only is it a bad idea to map page 0, but if we allowed
     it then user code that passed a null pointer to system calls
     could quite likely panic the kernel by way of null pointer
     assertions in memcpy(), etc. */
  if (phdr->p_vaddr < PGSIZE)
    return false;

  /* It's okay. */
  return true;
}

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool
load_segment (struct file *file, off_t ofs, uint8_t *upage,
              uint32_t read_bytes, uint32_t zero_bytes, bool writable)
{
  ASSERT ( (read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT (pg_ofs (upage) == 0);
  ASSERT (ofs % PGSIZE == 0);

  while (read_bytes > 0 || zero_bytes > 0)
    {
      /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
      size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
      size_t page_zero_bytes = PGSIZE - page_read_bytes;

      /* If the page contains no data from the file, do not associate it
         with the page. */
      if (page_zero_bytes == PGSIZE)
        {
          file = NULL;
          ofs = 0;
        }

      /* Add mapping to supplemental page table. */
      if (!spt_create_entry (file, ofs, upage, page_read_bytes, writable))
        return false;

      /* Advance. */
      read_bytes -= page_read_bytes;
      zero_bytes -= page_zero_bytes;
      upage += PGSIZE;
      ofs += PGSIZE;
    }
  return true;
}

/* Start address of the stack page of a new thread. */
#define STACK_PAGE_START  ((int) (PHYS_BASE - PGSIZE))
/* Calculates the page offset of ADDR. */
#define PAGE_OFFSET(addr) ((int) (addr) & PGMASK)
/* The maximum size argv may occupy. */
#define MAX_ARGV_SIZE   (PGSIZE/2)
/* Magic for the dummy return value of a new process. */
#define RETURN_MAGIC    0xFEFEB10C

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory.
   The new process' argv is stored at the top of the page and
   alligned for 4 byte access.
   Then the stack is setup with argc and argv (which are taken
   from AUX) as parameters and RETURN_MAGIC as return address.
   The top of the new stack is stored at *ESP.
   Returns false if an error occured, true otherwise. */
static bool
setup_stack (struct start_aux_data *aux, void **esp)
{
  int i, len;
  uint8_t *kpage = NULL;
  char **kpage_end;

  kpage = palloc_get_page (PAL_USER | PAL_ZERO);
  if (kpage == NULL)
    return false;

  /* The stack needs to be set up as follows:

     PHYS_BASE
     PHYS_BASE - 1 ...  the strings themselves (including a '\0' for each
                                    string and padding for byte alignment)
                        a pointer to each string (argv[X])
                        a null pointer marking end of args (argv[argc])
                        argv
                        argc
                        the dummy return address.

      Example: sed -i "s/a/b"

      PHYS_BASE - 1  ... 1 byte padding
                - 8  ... "s/a/b/\0"
                - 9  ... 1 byte padding
                - 12 ... "-i\0"
                - 16 ... "sed\0"
                - 20 ... argv[2] (points to PHYS_BASE - 8)
                - 24 ... argv[1] (points to PHYS_BASE - 12)
                - 28 ... argv[0] (points to PHYS_BASE - 16)
                - 32 ... argv (points to PHYS_BASE - 28)
                - 36 ... argc
                - 40 ... dummy return (MAGIC VALUE)

      esp is set to PHYS_BASE - 40.
  */

  /* Align and store the actual arg strings in reverse order on the
     stack. */
  kpage_end = (char **) (kpage + PGSIZE);
  for (i = aux->argc - 1; i >= 0; i--)
    {
      len = strlen (aux->argv[i]) + 1;

      /* Make sure the address where we store the arg is aligned. */
      kpage_end -= DIV_ROUND_UP (len, sizeof (int *));

      /* This takes too much space, die. */
      if (PAGE_OFFSET (kpage_end) < MAX_ARGV_SIZE)
        {
          return false;
        }

      strlcpy ( (char *) kpage_end, aux->argv[i], len);
      /* Calculate the address the arg will have in the new process
       * and store it in argv[i] (we don't need the old value). */
      aux->argv[i] = (char *) (STACK_PAGE_START
                               | PAGE_OFFSET (kpage_end));
    }

  /* Create space for argv (with argv[argc] = NULL). */
  kpage_end -= (aux->argc + 1);

  /* This takes too much space, die. */
  if (PAGE_OFFSET (kpage_end) < MAX_ARGV_SIZE)
    {
      return false;
    }

  /* Store the previously calculated argv addresses on the stack. */
  for (i = 0; i < aux->argc; i++)
    {
      kpage_end[i] = aux->argv[i];
    }
  /* By convention the last one is NULL. */
  kpage_end[aux->argc] = NULL;

  /* 1 for argv, 1 for argc, 1 for the return address. */
  kpage_end -= 3;

  kpage_end[0] = (char *) RETURN_MAGIC;
  kpage_end[1] = (char *) aux->argc;
  /* &argv[0] in the new process' address space. */
  kpage_end[2] = (char *) ( (int) STACK_PAGE_START
                            | PAGE_OFFSET (&kpage_end[3]));

  if (! install_page ( (uint8_t *) STACK_PAGE_START, kpage, true))
    {
      palloc_free_page (kpage);
      return false;
    }

  /* Set the stack pointer to point at the dummy return address. */
  *esp = (void *) (STACK_PAGE_START
                   | PAGE_OFFSET (kpage_end));

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
   if memory allocation fails.
   TODO: Delete once the move to vm.h is complete. */
static bool
install_page (void *upage, void *kpage, bool writable)
{
  struct thread *t = thread_current ();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page (t->pagedir, upage) == NULL
          && pagedir_set_page (t->pagedir, upage, kpage, writable));
}

static
bool
init_fd_table (struct fd_table *table)
{
  table->fds = palloc_get_page (PAL_ZERO);
  if (table->fds == NULL)
    return false;
  table->fd_cap = PGSIZE / sizeof (table->fds[0]);
  table->fd_free = 2;
  table->fd_max  = 1;
  return true;
}

/* Open the file with the given name; returns
   a file descriptor for this file if successful,
   and a negative value otherwise */
int
process_open_file (const char *fname)
{
  struct fd_table *fdt = &process_current()->fd_table;
  if (fdt->fd_free >= fdt->fd_cap)
    return -1;

  lock_acquire (&filesys_lock);
  struct file *f = filesys_open (fname);
  lock_release (&filesys_lock);

  if (f == NULL)
    return -1;

  int fd = fdt->fd_free++;
  fdt->fds[fd] = f;

  /* update index of free/max file descriptor index*/
  if (fd > fdt->fd_max) fdt->fd_max = fd;
  while (fdt->fds[fdt->fd_free] != NULL)
    {
      fdt->fd_free++;
      if (fdt->fd_free >= fdt->fd_cap)
        break;
    }
  return fd;
}

/* Get the file associated with the given file
   descriptor; return NULL if no file is associated
   with the given descriptor */
struct file *
process_get_file (int fd)
{
  struct fd_table *fdt = &process_current()->fd_table;
  if (fd < 2 || fd >= fdt->fd_cap || ! fdt->fds[fd])
    return NULL;
  return fdt->fds[fd];
}

/* Acquire global lock for the filesystem */
void process_lock_filesys (void)
{
  lock_acquire (&filesys_lock);
}

/* Release global filesystem lock */
void process_unlock_filesys (void)
{
  lock_release (&filesys_lock);
}

/* Close the file associated with the given file
   descriptor; returns true if close was successful */
bool
process_close_file (int fd)
{
  struct file *file = process_get_file (fd);
  if (file == NULL)
    return false;

  lock_acquire (&filesys_lock);
  file_close (file);
  lock_release (&filesys_lock);

  struct fd_table *fdt = &process_current()->fd_table;
  fdt->fds[fd] = NULL;

  /* update index of free/max file descriptor index*/
  if (fd < fdt->fd_free) fdt->fd_free = fd;
  while (fdt->fds[fdt->fd_max] == NULL)
    {
      fdt->fd_max--;
      if (fdt->fd_max < 2)
        break;
    }
  return true;
}
