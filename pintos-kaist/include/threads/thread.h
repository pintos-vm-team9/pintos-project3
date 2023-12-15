#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>
#include "threads/interrupt.h"
#include "synch.h"
#ifdef VM
#include "vm/vm.h"
#endif


/* States in a thread's life cycle. */
enum thread_status {
	THREAD_RUNNING,     /* Running thread. */
	THREAD_READY,       /* Not running but ready to run. */
	THREAD_BLOCKED,     /* Waiting for an event to trigger. */
	THREAD_DYING        /* About to be destroyed. */
};

struct exit_info {
    int pid;
    int exit_status;
    struct list_elem p_elem;
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t) -1)          /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0                       /* Lowest priority. */
#define PRI_DEFAULT 31                  /* Default priority. */
#define PRI_MAX 63                      /* Highest priority. */

/* macros for mlfqs
  n : integer,
  x,y : fixed point numbers*/
#define FC 16384  // 2^14, 고정소수점에서의 소수부를 나타내는 비트 수
#define convert_n_to_fp(n) ((n) * (FC)) // 정수 n을 고정소수점으로 변환
#define convert_x_to_int_round_to_zero(x) ((x) / (FC)) // 고정소수점 수 x를 정수로 변환 (반내림)
#define convert_x_to_int_round_to_nearest(x) ((x) >= 0 ? (((x) + ((FC) / 2)) / FC) : ((((x) - ((FC) / 2)) / FC))) // 고정소수점 수 x를 정수로 변환 (반올림)
#define add_x_and_y(x,y) ((x) + (y)) // 두 고정소수점 수 x와 y의 합
#define sub_y_from_x(x,y) ((x) - (y)) // 두 고정소수점 수 x와 y의 차 (x - y)
#define add_x_and_n(x,n) ((x)+((n) * (FC))) // 고정소수점 수 x와 정수 n의 합
#define sub_n_from_x(x,n) ((x) - ((n) * (FC))) // 고정소수점 수 x에서 정수 n을 뺀 값 (x - n)
#define mul_x_by_y(x,y) (((int64_t) (x)) * (y) / (FC)) // 두 고정소수점 수 x와 y의 곱
#define mul_x_by_n(x,n) ((x) * (n)) // 고정소수점 수 x와 정수 n의 곱
#define div_x_by_y(x,y) (((int64_t) (x)) * (FC) / (y)) // 고정소수점 수 x를 y로 나눈 값
#define div_x_by_n(x,n) ((x) / (n)) // 고정소수점 수 x를 정수 n으로 나눈 값


#define MIN_FD 3
#define MAX_FD 63
/* A kernel thread or user process.
 *
 * Each thread structure is stored in its own 4 kB page.  The
 * thread structure itself sits at the very bottom of the page
 * (at offset 0).  The rest of the page is reserved for the
 * thread's kernel stack, which grows downward from the top of
 * the page (at offset 4 kB).  Here's an illustration:
 *
 *      4 kB +---------------------------------+
 *           |          kernel stack           |
 *           |                |                |
 *           |                |                |
 *           |                V                |
 *           |         grows downward          |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           |                                 |
 *           +---------------------------------+
 *           |              magic              |
 *           |            intr_frame           |
 *           |                :                |
 *           |                :                |
 *           |               name              |
 *           |              status             |
 *      0 kB +---------------------------------+
 *
 * The upshot of this is twofold:
 *
 *    1. First, `struct thread' must not be allowed to grow too
 *       big.  If it does, then there will not be enough room for
 *       the kernel stack.  Our base `struct thread' is only a
 *       few bytes in size.  It probably should stay well under 1
 *       kB.
 *
 *    2. Second, kernel stacks must not be allowed to grow too
 *       large.  If a stack overflows, it will corrupt the thread
 *       state.  Thus, kernel functions should not allocate large
 *       structures or arrays as non-static local variables.  Use
 *       dynamic allocation with malloc() or palloc_get_page()
 *       instead.
 *
 * The first symptom of either of these problems will probably be
 * an assertion failure in thread_current(), which checks that
 * the `magic' member of the running thread's `struct thread' is
 * set to THREAD_MAGIC.  Stack overflow will normally change this
 * value, triggering the assertion. */
/* The `elem' member has a dual purpose.  It can be an element in
 * the run queue (thread.c), or it can be an element in a
 * semaphore wait list (synch.c).  It can be used these two ways
 * only because they are mutually exclusive: only a thread in the
 * ready state is on the run queue, whereas only a thread in the
 * blocked state is on a semaphore wait list. */
struct thread {
	/* Owned by thread.c. */
	tid_t tid;                          /* Thread identifier. */
	enum thread_status status;          /* Thread state. */
	char name[16];                      /* Name (for debugging purposes). */
	int priority;                       /* Priority. */
	/* TO DO: add local tick(the time to wake up)*/
	int64_t wakeup_tick;
	/* Shared between thread.c and synch.c. */
	struct list_elem elem;              /* List element. */
	
	struct list donations; // 나에게 후원한 스레드들 리스트
	struct list_elem d_elem; // 내가 후원할 스레드에게 내 정보를 저장하게 함
	struct lock *wait_on_lock; // 내가 기다리는 락
	int original_priority; // 내 priority가 후원을 받아서 높아져도 원래 priority를 저장하기 위해

	int nice;
	int recent_cpu;

	int exit_status;
	char p_name[256];

	struct list child_list;
	struct list_elem c_elem; // child elem..
	struct file *fdt[64];
	int waiting_child; // 필요 x 
	struct thread* parent;
	struct file *loaded_file;
	struct semaphore fork_sema;
	struct semaphore wait_sema;
	struct semaphore exit_sema;
	struct intr_frame parent_if;
	int child_exit_status;
	int is_exit;
	struct list exit_child_list;
	//struct list killed_list;
	//struct list_elem k_elem;
	
#ifdef USERPROG
	/* Owned by userprog/process.c. */
	uint64_t *pml4;                     /* Page map level 4 */
	
#endif
#ifdef VM
	/* Table for whole virtual memory owned by thread. */
	struct supplemental_page_table spt;
#endif

	/* Owned by thread.c. */
	struct intr_frame tf;               /* Information for switching */
	unsigned magic;                     /* Detects stack overflow. */
};


/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init (void);
void thread_start (void);

void thread_tick (void);
void thread_print_stats (void);

typedef void thread_func (void *aux);
tid_t thread_create (const char *name, int priority, thread_func *, void *);

void thread_block (void);
void thread_unblock (struct thread *);

struct thread *thread_current (void);
tid_t thread_tid (void);
const char *thread_name (void);

void thread_exit (void) NO_RETURN;
void thread_yield (void);

int thread_get_priority (void);
void thread_set_priority (int);

int thread_get_nice (void);
void thread_set_nice (int);
int thread_get_recent_cpu (void);
int thread_get_load_avg (void);

void do_iret (struct intr_frame *tf);

struct list ready_list;
struct list sleep_list; 
struct list wait_list;
void thread_test_preemption (void);
struct thread *idle_thread;
int READY_THREADS;
int LOAD_AVG;
#endif /* threads/thread.h */
