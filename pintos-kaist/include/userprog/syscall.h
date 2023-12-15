#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);

struct lock sysfile_lock;
struct lock syswait_lock;

void sys_exit(int status);
#endif /* userprog/syscall.h */
