#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

/* In the current implementation, the capacity is fixed to 1024 (PGSIZE/4) */
struct fd_table {
    struct file** fds;
    int fd_free;    /* lowest-index free FD table entry */
    int fd_max;     /* highest-index used FD table entry */
    int fd_cap;     /* FD table capacity */
};

struct process {
    /* process tree */
    tid_t thread_id;
    tid_t parent_tid;
    struct list_elem parentelem;       /* Owned by parent */

    /* communication with parent process */
    struct semaphore exit_sem;
    struct lock exit_lock;
    int exit_status;

    /* files */
    struct file *executable;           /* Loaded executable, if any. */
    struct fd_table fd_table;          /* File descriptor table */

    /* Owned by syscall.c */
    void* syscall_buffer;
    size_t syscall_buffer_page_cnt;
};

void process_init (void);
struct process* process_current (void);
tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

int process_open_file(const char* fname);
struct file* process_get_file(int fd);
void process_lock_filesys (void);
void process_unlock_filesys (void);
bool process_close_file(int fd);

#endif /* userprog/process.h */
