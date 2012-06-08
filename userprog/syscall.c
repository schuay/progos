#include <stdio.h>
#include <syscall-nr.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "lib/string.h"
#include "threads/interrupt.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/syscall.h"

#define STACK_SLOT_SIZE sizeof(int)

/* Prototypes for Utilities */
static int get_user (const uint8_t *uaddr);
static bool put_user (uint8_t *udst, uint8_t byte);
static void *memcpy_from_user (void *kaddr, void *uaddr, size_t bytes);
static void *memcpy_to_user (void *kaddr, void *addr, size_t bytes);
static void *copy_string_arg (void *usp, bool *segfault);
static void free_string_arg_buf (void *kbuf);

/* Reads a byte at user virtual address UADDR.
   UADDR must be below PHYS_BASE.
   Returns the byte value if successful, -1 if a segfault
   occurred. */
static int
get_user (const uint8_t *uaddr)
{
  int result;
  asm ("movl $1f, %0; "  /* save eip in eax */
       "movzbl %1, %0; " /* read byte from user memory into eax */
       "1:"              /* continue here on page fault, with eax set to -1 */
       : "=&a" (result) : "m" (*uaddr));
  return result;
}

/* Writes BYTE to user address UDST.
   UDST must be below PHYS_BASE.
   Returns true if successful, false if a segfault occurred. */
static bool
put_user (uint8_t *udst, uint8_t byte)
{
  int error_code;
  asm ("movl $1f, %0;" /* save EIP in EAX */
       "movb %b2, %1;" /* write byte to user memory  */
       "1:"            /* continue here on page fault, with eax set to -1 */
       : "=&a" (error_code), "=m" (*udst) : "q" (byte));
  return error_code != -1;
}

/* Copy bytes from user space; returns NULL if a segfault
   occured, and kaddr otherwise */
static void *
memcpy_from_user (void *kaddr, void *uaddr, size_t bytes)
{
  uint8_t *kp = kaddr;
  size_t i;
  if (! is_user_vaddr (uaddr) ||
      ! is_user_vaddr (uaddr + bytes - 1))
    return false;
  for (i = 0; i < bytes; i++)
    {
      int b = get_user (uaddr + i);
      if (b < 0)
        break; /* segfault */
      else
        kp[i] = b;
    }
  if (i != bytes)
    return NULL; /* segfault */
  return kaddr;
}

/* Copy bytes to user space; returns NULL if a segfault
   occured, and uaddr otherwise */
static void *
memcpy_to_user (void *uaddr, void *kaddr, size_t bytes)
{
  uint8_t *kp = kaddr;
  size_t i;
  if (! is_user_vaddr (uaddr) ||
      ! is_user_vaddr (uaddr + bytes - 1))
    return false;
  for (i = 0; i < bytes; i++)
    {
      if (! put_user (uaddr + i, kp[i]))
        break; /* segfault */
    }
  if (i != bytes)
    return NULL; /* segfault */
  return uaddr;
}

/* Copy string (at most cnt bytes) from user memory to the kernel address
   `kaddr`. The number of bytes copied is returned; 0 indicates a segfault. */
static size_t
strncpy_from_user (void *kaddr, void *uaddr, size_t cnt)
{
  uint8_t *kp = (uint8_t *) kaddr;
  size_t i;
  int c = 1;
  for (i = 0; i < cnt && c; i++)
    {
      if (! is_user_vaddr (uaddr + i))
        return 0; /* sefault */
      c = get_user (uaddr + i);
      if (c < 0)
        return 0; /* segfault */
      kp[i] = c;
    }
  return i;
}

/* Copy a value of scalar type `typeof(*kdst)` from user space pointer
  `usrc` to kernel space variable pointed to by `kdst`. Returns
  false on segfault, and true otherwise. */
#define copy_from_user(kdst, usrc) \
    (memcpy_from_user (kdst, usrc, sizeof (*kdst)) != NULL)

/* Takes user space stack pointer, which points to a string
   in user space. Copies that string (at most PGSIZE bytes)
   to a freshly allocated buffer in kernel space. Reurns NULL on
   error; on a segfault, additionally sets `segfault` to true */
static void *
copy_string_arg (void *usp, bool *segfault)
{
  size_t bytes_copied;
  char *uptr;
  char *kpage;
  if (! copy_from_user (&uptr, usp))
    {
      *segfault = true;
      return NULL;
    }
  kpage = palloc_get_page (PAL_ZERO);
  if (kpage == NULL)
    return NULL;
  bytes_copied = strncpy_from_user (kpage, uptr, PGSIZE);
  if (bytes_copied == 0)
    {
      *segfault = true;
      palloc_free_page (kpage);
      return NULL;
    }
  if (kpage[bytes_copied - 1] != '\0')
    {
      palloc_free_page (kpage);
      return NULL;
    };
  return kpage;
}

/* free buffer allocated by `copy_string_arg` */
static void free_string_arg_buf (void *kbuf)
{
  palloc_free_page (kbuf);
}

/* Stack slot address */
#define STACK_ADDR(sp, slot) (sp + STACK_SLOT_SIZE*slot)

/* syscall handler prototype */
static void syscall_handler (struct intr_frame *);

typedef int (handler) (void *sp, bool *segfault);

/* Prototypes for syscall handlers */
static handler
syscall_halt,
syscall_exit,
syscall_write,
syscall_wait ,
syscall_exec,
syscall_create,
syscall_remove,
syscall_open,
syscall_filesize,
syscall_read,
syscall_seek,
syscall_tell,
syscall_close,
syscall_mmap,
syscall_munmap;

/* Register syscall_handler for interrupt 0x30 */
void
syscall_init (void)
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

/* Syscall handler, delegating known syscalls to the respective implementations */
static void
syscall_handler (struct intr_frame *f)
{
  int syscall_nr;
  handler *fp;
  bool segfault = false;
  int result;
  void *sp = f->esp;

  /* The system call number and the arguments are on the stack */
  if (! copy_from_user (&syscall_nr, sp))
    goto fail;
  switch (syscall_nr)
    {
    case SYS_HALT:
      fp = syscall_halt;
      break;
    case SYS_EXIT:
      fp = syscall_exit;
      break;
    case SYS_EXEC:
      fp = syscall_exec;
      break;
    case SYS_WAIT:
      fp = syscall_wait;
      break;
    case SYS_CREATE:
      fp = syscall_create;
      break;
    case SYS_REMOVE:
      fp = syscall_remove;
      break;
    case SYS_OPEN:
      fp = syscall_open;
      break;
    case SYS_FILESIZE:
      fp = syscall_filesize;
      break;
    case SYS_READ:
      fp = syscall_read;
      break;
    case SYS_WRITE:
      fp = syscall_write;
      break;
    case SYS_SEEK:
      fp = syscall_seek;
      break;
    case SYS_TELL:
      fp = syscall_tell;
      break;
    case SYS_CLOSE:
      fp = syscall_close;
      break;
    case SYS_MMAP:
      fp = syscall_mmap;
      break;
    case SYS_MUNMAP:
      fp = syscall_munmap;
      break;
    default:
      goto fail;
    }
  result = fp (sp, &segfault);
  if (segfault)
    goto fail;
  f->eax = result;
  return;

fail:
  process_current()->exit_status = -1;
  thread_exit ();
}

/* Shutdown machine */
static int
syscall_halt (void *sp UNUSED, bool *segfault UNUSED)
{
  shutdown ();
  NOT_REACHED ();
}

/* Exit current process with given exit code */
static int
syscall_exit (void *sp, bool *segfault)
{
  int exit_status;
  if (! copy_from_user (&exit_status, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return -1;
    }
  process_current()->exit_status = exit_status;
  thread_exit ();
  NOT_REACHED ();
}

/* Spawn new process executing the supplied command */
static int
syscall_exec (void *sp, bool *segfault)
{
  char *kbuf;
  int result = TID_ERROR;
  if ( (kbuf = copy_string_arg (STACK_ADDR (sp, 1), segfault)) != NULL)
    {
      result = process_execute (kbuf);
      free_string_arg_buf (kbuf);
    }
  return result;
}

/* Wait until specified process exits */
static int
syscall_wait (void *sp, bool *segfault)
{
  tid_t arg;
  if (! copy_from_user (&arg, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return 0;
    }
  return process_wait (arg);
}

/* Create a new file with given initial size */
static int
syscall_create (void *sp, bool *segfault)
{
  bool success = false;
  char *fname;
  int initial_size;

  if (! copy_from_user (&initial_size, STACK_ADDR (sp, 2)))
    {
      *segfault = true;
      return false;
    }
  if ( (fname = copy_string_arg (STACK_ADDR (sp, 1), segfault)) == NULL)
    return false;

  process_lock_filesys ();
  success = filesys_create (fname, initial_size);
  process_unlock_filesys ();
  free_string_arg_buf (fname);
  return success;
}

/* Remove name file, returns true if successful */
static int
syscall_remove (void *sp, bool *segfault)
{
  bool success;
  char *fname;

  if ( (fname = copy_string_arg (STACK_ADDR (sp, 1), segfault)) == NULL)
    return false;
  process_lock_filesys ();
  success = filesys_remove (fname);
  process_unlock_filesys ();
  free_string_arg_buf (fname);
  return (int) success;
}

/* Open file, returning non-negative file descriptor if successful */
static int
syscall_open (void *sp, bool *segfault)
{
  char *fname;
  int fd;
  if ( (fname = copy_string_arg (STACK_ADDR (sp, 1), segfault)) == NULL)
    return false;
  fd = process_open_file (fname);
  free_string_arg_buf (fname);
  return fd;
}

/* Return size of file described by file descriptor */
static int
syscall_filesize (void *sp, bool *segfault)
{
  int fd;
  struct file *f;
  int size;

  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return -1;
    }
  if ( (f = process_get_file (fd)) == NULL)
    return -1;
  process_lock_filesys ();
  size = inode_length (file_get_inode (f));
  process_unlock_filesys ();
  return size;
}

/* Read bytes from the file referenced by the given file
   descriptor into the supplied user space buffer, returning
   number of bytes read. */
static int
syscall_read (void *sp, bool *segfault)
{
  int fd;
  uint8_t *user_buffer;
  size_t size, bytes_to_read;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)) ||
      ! copy_from_user (&user_buffer, STACK_ADDR (sp, 2)) ||
      ! copy_from_user (&size, STACK_ADDR (sp, 3)))
    {
      *segfault = true;
      return -1;
    }

  /* ensure buffer is in user space */
  if (! is_user_vaddr (user_buffer) ||
      ! is_user_vaddr (user_buffer + size - 1))
    {
      *segfault = true;
      return -1;
    }

  bytes_to_read = size;
  /* handle stdin */
  if (fd == STDIN_FILENO)
    {
      char c;
      while (bytes_to_read--)
        {
          c = input_getc ();
          if (! put_user (user_buffer++, c))
            {
              *segfault = true;
              return -1;
            }
        }
      return size;
    }
  /* get file */
  struct file *file = process_get_file (fd);
  if (file == NULL)
    return -1;

  char *kbuf = palloc_get_page (0);
  if (kbuf == NULL)
    return -1;

  /* read loop */
  do
    {
      int bytes_read;
      int blocksize = bytes_to_read;
      if (bytes_to_read > PGSIZE)
        blocksize = PGSIZE;

      /* read bytes */
      process_lock_filesys ();
      bytes_read = file_read (file, kbuf, blocksize);
      process_unlock_filesys ();

      /* Stop when EOF has been reached */
      if (bytes_read == 0)
        break;
      bytes_to_read -= bytes_read;
      if (! memcpy_to_user (user_buffer, kbuf, bytes_read))
        {
          *segfault = true;
          break;
        }
      user_buffer += bytes_read;
    }
  while (bytes_to_read > 0);

  palloc_free_page (kbuf);
  return size - bytes_to_read;
}

/* Write bytes from user buffer into the specified
   file, returning number of bytes written. */
static int
syscall_write (void *sp, bool *segfault)
{
  int fd;
  size_t size, bytes_to_write;
  char *user_buffer;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)) ||
      ! copy_from_user (&user_buffer, STACK_ADDR (sp, 2)) ||
      ! copy_from_user (&size, STACK_ADDR (sp, 3)))
    {
      *segfault = true;
      return -1;
    }

  /* ensure buffer is in user space */
  if (! is_user_vaddr (user_buffer) ||
      ! is_user_vaddr (user_buffer + size - 1))
    {
      *segfault = true;
      return -1;
    }

  /* get file handle */
  struct file *file = NULL;
  if (fd != STDOUT_FILENO)
    {
      file = process_get_file (fd);
      if (file == NULL)
        return -1;
    }

  /* allocate kernel buffer */
  char *kbuf = palloc_get_page (0);
  if (kbuf == NULL)
    return -1;

  /* write loop */
  bytes_to_write = size;
  do
    {
      int blocksize = bytes_to_write;
      if (bytes_to_write > PGSIZE)
        blocksize = PGSIZE;
      if (memcpy_from_user (kbuf, user_buffer, blocksize) == NULL)
        {
          *segfault = true;
          break;
        }
      if (fd == STDOUT_FILENO)
        {
          putbuf (kbuf, blocksize);
          bytes_to_write -= blocksize;
        }
      else
        {
          int bytes_written = 0;
          int bytes_left_filesys = blocksize;

          process_lock_filesys ();
          while (bytes_left_filesys > 0)
            {
              bytes_written = file_write (file, kbuf, bytes_left_filesys);
              if (bytes_written <= 0)
                {
                  break;
                }
              bytes_left_filesys -= bytes_written;
            }
          process_unlock_filesys ();

          if (bytes_written <= 0)
            break;
          bytes_to_write -= blocksize;
        }
      user_buffer += blocksize;
    }
  while (bytes_to_write > 0);

  /* return bytes written */
  palloc_free_page (kbuf);
  return size - bytes_to_write;
}

/* Change the position where the next byte will be read or written */
static int
syscall_seek (void *sp, bool *segfault)
{
  int fd;
  off_t new_pos;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)) ||
      ! copy_from_user (&new_pos, STACK_ADDR (sp, 2)))
    {
      *segfault = true;
      return 0;
    }

  /* no way to return something sensible (void function) */
  struct file *file = process_get_file (fd);
  if (file == NULL)
    return 0;

  process_lock_filesys ();
  file_seek (file, new_pos);
  process_unlock_filesys ();
  return 0;
}

/* Returns the position of the next byte to be read or written */
static int
syscall_tell (void *sp, bool *segfault)
{
  int fd;
  unsigned r = 0;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return 0;
    }

  /* no way to return something sensible function */
  struct file *file = process_get_file (fd);
  if (file == NULL)
    return 0;

  process_lock_filesys ();
  r = file_tell (file);
  process_unlock_filesys ();
  return r;
}

/* Close the given file */
static int
syscall_close (void *sp, bool *segfault)
{
  int fd;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return 0;
    }

  /* no way to return something sensible function (void) */
  (void) process_close_file (fd);
  return 0;
}

/* Memory-map the given file */
static int
syscall_mmap (void *sp, bool *segfault)
{
  int fd;
  void *addr;

  /* get arguments */
  if (! copy_from_user (&fd, STACK_ADDR (sp, 1)) ||
      ! copy_from_user (&addr, STACK_ADDR (sp, 2)))
    {
      *segfault = true;
      return 0;
    }

  return process_mmap_file (fd, addr);
}

/* Memory-unmap the given file */
static int
syscall_munmap (void *sp, bool *segfault)
{
  mapid_t id;

  /* get arguments */
  if (! copy_from_user (&id, STACK_ADDR (sp, 1)))
    {
      *segfault = true;
      return 0;
    }

  process_munmap_file (id);

  return 0;
}
