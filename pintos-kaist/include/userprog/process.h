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

//project3
static bool lazy_load_segment (struct page *page, void *aux);

struct box { //파일의 특정 부분을 읽거나 쓰기 위한 정보를 저장하는 것, 스왑 영역에서 페이지를 읽거나 쓰는 데에도 사용
    struct file *file; //파일을 가리키는 포인터
    off_t ofs; //파일 시작 오프셋
    size_t page_read_bytes; //파일에서 읽은 바이트 수
};
bool setup_stack (struct intr_frame *if_);
#endif /* userprog/process.h */
