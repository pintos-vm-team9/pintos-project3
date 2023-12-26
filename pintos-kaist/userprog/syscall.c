#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/loader.h"
#include "userprog/gdt.h"
#include "threads/flags.h"
#include "intrinsic.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "devices/input.h"
#include "lib/kernel/console.h"
#include "userprog/process.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "lib/string.h"
void syscall_entry (void);
void syscall_handler (struct intr_frame *);
void sys_exit(int status);

/* System call.
 *
 * Previously system call services was handled by the interrupt handler
 * (e.g. int 0x80 in linux). However, in x86-64, the manufacturer supplies
 * efficient path for requesting the system call, the `syscall` instruction.
 *
 * The syscall instruction works by reading the values from the the Model
 * Specific Register (MSR). For the details, see the manual. */

#define MSR_STAR 0xc0000081         /* Segment selector msr */
#define MSR_LSTAR 0xc0000082        /* Long mode SYSCALL target */
#define MSR_SYSCALL_MASK 0xc0000084 /* Mask for the eflags */
typedef int pid_t;
void sys_halt(void);
void sys_exit(int status);
pid_t sys_fork(const char* thread_name, struct intr_frame *f);
int sys_exec(const char *cmd_line);
int sys_wait(pid_t pid);
bool sys_create(const char *file, unsigned initial_size,uintptr_t rsp);
bool sys_remove(const char *file);
int sys_open(const char *file);
int sys_filesize(int fd);
int sys_read(int fd, void *buffer, unsigned size);
int sys_write(int fd, const void* buffer, unsigned size);
void sys_seek(int fd, unsigned position);
unsigned sys_tell(int fd);
void sys_close(int fd);
bool pml4_for_each (uint64_t *pml4, pte_for_each_func *func, void *aux);
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset);

void
syscall_init (void) {
	write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48  |
			((uint64_t)SEL_KCSEG) << 32);
	write_msr(MSR_LSTAR, (uint64_t) syscall_entry);

	/* The interrupt service rountine should not serve any interrupts
	 * until the syscall_entry swaps the userland stack to the kernel
	 * mode stack. Therefore, we masked the FLAG_FL. */
	write_msr(MSR_SYSCALL_MASK,
			FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);

	lock_init(&sysfile_lock);
	lock_init(&syswait_lock);
}

/* The main system call interface */
void
syscall_handler (struct intr_frame *f UNUSED) {

	// + project 3 +
	#ifdef VM
        thread_current()->rsp_stack = f->rsp; 
    #endif

	switch(f->R.rax){
		case SYS_HALT:
			sys_halt(); // done
			break;
		case SYS_EXIT:
			sys_exit(f->R.rdi); 
			// exit할 때 부모, 형제 스레드에게 해야할 것 해줘야함
			// deallocate the FDT, close all files
			break;
		case SYS_FORK:
			f->R.rax = sys_fork(f->R.rdi, f); // not yet
			break;
		case SYS_EXEC:
			f->R.rax = sys_exec(f->R.rdi); // not yet
			break;
		case SYS_WAIT:
			f->R.rax = sys_wait(f->R.rdi);
			break;
		case SYS_CREATE:
			f->R.rax = sys_create(f->R.rdi, f->R.rsi,f->rsp); // done
			break;
		case SYS_REMOVE:
			f->R.rax = sys_remove(f->R.rdi);
			break;
		case SYS_OPEN:
			f->R.rax = sys_open(f->R.rdi);
			break;
		case SYS_FILESIZE:
			f->R.rax = sys_filesize(f->R.rdi);
			break;
		case SYS_READ:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 1);
			f->R.rax = sys_read(f->R.rdi,f->R.rsi,f->R.rdx);
			break;
		case SYS_WRITE:
			check_valid_buffer(f->R.rsi, f->R.rdx, f->rsp, 0);
			f->R.rax = sys_write(f->R.rdi,f->R.rsi,f->R.rdx);
			break;
		case SYS_SEEK:
			sys_seek (f->R.rdi,f->R.rsi);
			break;
		case SYS_TELL:
			sys_tell(f->R.rdi);
			break;
		case SYS_CLOSE:
			sys_close(f->R.rdi);
			break;
		// project 3
        case SYS_MMAP:
            f->R.rax = mmap(f->R.rdi, f->R.rsi, f->R.rdx, f->R.r10, f->R.r8);
            break;
        case SYS_MUNMAP:
            munmap(f->R.rdi);
            break;
		default:
		 	sys_exit(-1);
			break;
	}
}

// + project 3 +
void *mmap(void *addr, size_t length, int writable, int fd, off_t offset){
    // offset이 정렬되지 않았을 때
    if (offset % PGSIZE != 0){
        return NULL;
    }
    if(pg_round_down(addr) != addr || is_kernel_vaddr(addr) || addr == NULL || (long long)length <=0)
        return NULL;
    // console input, output은 mapping x
    if(fd == 0 || fd == 1)
        sys_exit(-1);
    // overlap
    if(spt_find_page(&thread_current()->spt, addr))
        return NULL;

	
    struct file *target = process_get_file(fd);
    if(target == NULL)
        return NULL;

    void *ret = do_mmap(addr, length, writable, target, offset);

    return ret;
}

void munmap(void *addr){
    do_munmap(addr);
}

// end project 3 +

void
sys_halt(void){
	power_off();
}

void
sys_exit(int status){
	thread_current()->exit_status = status;

	printf("%s: exit(%d)\n",thread_current()->name, thread_current()->exit_status);
	thread_exit();
}

struct thread*
get_child_process(pid_t pid){
	struct thread * curr = thread_current();
	struct list_elem *e;
	struct thread * child;
	for (e = list_begin (&curr->child_list); e != list_end (&curr->child_list); e = list_next (e)){
		child = list_entry(e,struct thread,c_elem);
		if(child->tid == pid){
			return child;
		}
	}
	return NULL; // not exist!
}

void
remove_child_process(pid_t pid){ // 자식 스레드의 메모리도 해제 해야 함? 즉, thread_exit()  사용해야함?
	struct thread * curr = thread_current();
	struct list_elem *e;
	struct thread * child;
	for (e = list_begin (&curr->child_list); e != list_end (&curr->child_list); e = list_next (e)){
		child = list_entry(e,struct thread,c_elem);
		if(child->tid == pid){
			list_remove(e);
			return;
		}
	}
	return; // not exist!
}

pid_t
sys_fork(const char* thread_name,struct intr_frame *f ){
	
	int pid = process_fork(thread_name,f); 
	
	if (pid == TID_ERROR) return -1;

	struct thread * child = get_child_process(pid); 
	
	sema_down(&child->fork_sema);
	
	if (child->exit_status == -1) {
		return -1;
	} 
	return pid;
}

int
sys_exec(const char *cmd_line){
	if(!pml4_get_page(thread_current()->pml4,cmd_line)) { // 일단 아님..
		sys_exit(-1);
	}

	if(cmd_line[0] == '\0') sys_exit(-1); 
	char *fn_copy;
    int dst_len = strlen(cmd_line)+1;
    fn_copy = palloc_get_page (PAL_ZERO);

    if (fn_copy == NULL) {
		palloc_free_page(fn_copy);
		return -1;
	}
	
    memcpy(fn_copy, cmd_line, dst_len);
	
	// file_close(fn_copy);
	if (process_exec (fn_copy) < 0)
		sys_exit(-1);
	//return -1;
}

int
get_exit_child_process(pid_t pid){
	struct thread * curr = thread_current();
	struct list_elem *e;
	struct exit_info * cur_info;
	for (e = list_begin (&curr->exit_child_list); e != list_end (&curr->exit_child_list); e = list_next (e)){
		cur_info = list_entry(e,struct exit_info,p_elem);
		if(cur_info->pid == pid){
			int i = cur_info->exit_status;
			return i;
		}
	}
	return -1; // not exist!
}

int
sys_wait(pid_t pid){ 
	// 자식 끝날때까지 기다리는 함수
	if(thread_current()->waiting_child == pid) return -1; // for test

	int exit_pid;
	lock_acquire(&syswait_lock);
	if(exit_pid = get_exit_child_process(pid) != -1) {
		thread_current()->waiting_child = pid;
		lock_release(&syswait_lock);
		//return exit_pid;
		return get_exit_child_process(pid);
	}
	thread_current()->waiting_child = pid;
	lock_release(&syswait_lock);

	return process_wait(pid);
}

bool
sys_create(const char *file, unsigned initial_size,uintptr_t rsp){
	/* 1. 잘못된 주소로 접근한 경우 -> exit(-1)
	   2. 너무 긴 file 이름인 경우 -> return 0;
	   3. 
	*/

	if(!pml4_get_page(thread_current()->pml4,file)) { // file 주소에 할당된 페이지가 있나없나.. 
		sys_exit(-1);
	}

	return filesys_create(file,initial_size);
}

bool
sys_remove(const char* file){
	if(!pml4_get_page(thread_current()->pml4,file)) { // 일단 아님..
		sys_exit(-1);
	}

	return filesys_remove(file);	
}

int
sys_open(const char *file){
	if(!is_user_vaddr(file)) return -1;
	if(!pml4_get_page(thread_current()->pml4,file)) {
		sys_exit(-1);
	}
	if(file[0] == '\0')return -1; // empty에서 출력 형식 맞추기 
	if(file == NULL) sys_exit(-1);
	
	lock_acquire(&sysfile_lock);
	for(int i=MIN_FD; i<= MAX_FD;i++){
		if (thread_current()->fdt[i] == NULL){
			struct file *fd = filesys_open(file);
			if ( !fd ) {
				lock_release(&sysfile_lock);
				return -1;
			}
			else{
				// printf("\nopen : fd = %d\n",i);
				thread_current()->fdt[i] = fd;
				lock_release(&sysfile_lock);
				return i;
			}
		}
	}

	lock_release(&sysfile_lock);
	return -1; // 실패	
}

int 
sys_filesize(int fd){
	return file_length(thread_current()->fdt[fd]);
}

int
sys_read(int fd, void *buffer, unsigned size){
	
	// if(!pml4_get_page(thread_current()->pml4,buffer)) { 
	// 	sys_exit(-1);
	// }
	
	lock_acquire(&sysfile_lock);
	int file_size;	
	if( fd == 0){
		file_size = input_getc();
		lock_release(&sysfile_lock);
		return file_size;
	}
	  
	if( fd < 0 || fd > 63){

		lock_release(&sysfile_lock);
		return -1;
	}
	// lock 잡아주기
	if( thread_current()->fdt[fd] == NULL){
		
		lock_release(&sysfile_lock);	
		return -1;
	}
	// printf("\nread : fd = %d\n",fd);
	file_size = file_read(thread_current()->fdt[fd],buffer,size);
	lock_release(&sysfile_lock);

	return file_size;
}
int
sys_write(int fd, const void* buffer, unsigned size){
	// printf("sys_write inside!\n");
	// printf("fd:%d, buffer:%s",fd,buffer);
	// if(!pml4_get_page(thread_current()->pml4,buffer)) { 
	// 	sys_exit(-1);
	// }
	lock_acquire(&sysfile_lock);
	if(fd == 1){ // stdout
		// use putbuf.. 로 바꿔야함
		//printf("%s",buffer); 
		putbuf(buffer,size); //오류가 있쌈;;;;;;
		lock_release(&sysfile_lock);
		return size;//putbuf(&buffer,sizeof(buffer));
	}
	if ( fd> 63 || fd < 0 ) {
		lock_release(&sysfile_lock);
		sys_exit(-1);
	}
	if ( thread_current()->fdt[fd] == NULL) {
		lock_release(&sysfile_lock);
		return 0; // 아직 해당 fd가 존재하지 않는 경우 -> return 0
	}
	// printf("\nwrite : fd = %d\n",fd);
	int write_result = file_write(thread_current()->fdt[fd], buffer, size);
	lock_release(&sysfile_lock);
	return write_result;
}

void
sys_seek(int fd, unsigned position){ // 예외처리 아직 안함
	file_seek(thread_current()->fdt[fd],position);
	return;
}

unsigned
sys_tell(int fd){
	return file_tell(thread_current()->fdt[fd]);
}

void
sys_close(int fd){
	if (fd < 0 || fd > 63) return;
	if (thread_current()->fdt[fd] == NULL) return;
	
	file_close(thread_current()->fdt[fd]);
	thread_current()->fdt[fd] = NULL;
	return;
}

struct page * check_address(void *addr){
    if(is_kernel_vaddr(addr)){
        sys_exit(-1);
    }
    return spt_find_page(&thread_current()->spt,addr);
}

void check_valid_buffer(void* buffer, unsigned size, void* rsp, bool to_write){
    for(int i=0; i<size; i++){
        struct page* page = check_address(buffer + i);
        if(page == NULL)
            sys_exit(-1);
        if(to_write == true && page->writable == false)
            sys_exit(-1);
    }
}