#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);
bool duplicate_pte (uint64_t *pte, void *va, void *aux);
bool install_page (void *upage, void *kpage, bool writable);
bool setup_stack (struct intr_frame *if_);

static bool lazy_load_segment (struct page *page, void *aux);

// + project 3 +
struct container{
    struct file *file;
    off_t offset;
    size_t page_read_bytes;
};

#endif /* userprog/process.h */