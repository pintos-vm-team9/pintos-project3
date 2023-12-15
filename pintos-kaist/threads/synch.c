/* This file is derived from source code for the Nachos
   instructional operating system.  The Nachos copyright notice
   is reproduced in full below. */

/* Copyright (c) 1992-1996 The Regents of the University of California.
   All rights reserved.

   Permission to use, copy, modify, and distribute this software
   and its documentation for any purpose, without fee, and
   without written agreement is hereby granted, provided that the
   above copyright notice and the following two paragraphs appear
   in all copies of this software.

   IN NO EVENT SHALL THE UNIVERSITY OF CALIFORNIA BE LIABLE TO
   ANY PARTY FOR DIRECT, INDIRECT, SPECIAL, INCIDENTAL, OR
   CONSEQUENTIAL DAMAGES ARISING OUT OF THE USE OF THIS SOFTWARE
   AND ITS DOCUMENTATION, EVEN IF THE UNIVERSITY OF CALIFORNIA
   HAS BEEN ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

   THE UNIVERSITY OF CALIFORNIA SPECIFICALLY DISCLAIMS ANY
   WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
   WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
   PURPOSE.  THE SOFTWARE PROVIDED HEREUNDER IS ON AN "AS IS"
   BASIS, AND THE UNIVERSITY OF CALIFORNIA HAS NO OBLIGATION TO
   PROVIDE MAINTENANCE, SUPPORT, UPDATES, ENHANCEMENTS, OR
   MODIFICATIONS.
   */

#include "threads/synch.h"
#include <stdio.h>
#include <string.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

#define MAX(a, b) ((a) > (b) ? (a) : (b))
#define MIN(a, b) ((a) < (b) ? (a) : (b))

bool cmp_sema_priority(const struct list_elem *e, const struct list_elem *before, void * aux);
bool comapare_priority(struct list_elem *element, struct list_elem *before,void * aux);
/* Initializes semaphore SEMA to VALUE.  A semaphore is a
   nonnegative integer along with two atomic operators for
   manipulating it:

   - down or "P": wait for the value to become positive, then
   decrement it.

   - up or "V": increment the value (and wake up one waiting
   thread, if any). */
   
bool cmp_sema_priority(const struct list_elem *e, const struct list_elem *before, void * aux){
	//struct thread * c= list_entry(list_begin(&(list_entry(e,struct semaphore_elem,elem)->semaphore.waiters)),struct thread,elem)->name;
	struct semaphore_elem * a = list_entry(e,struct semaphore_elem,elem);
	struct semaphore_elem * a_before = list_entry(before,struct semaphore_elem,elem);

	struct list_elem * b = list_begin(&(a->semaphore.waiters));
	struct list_elem * b_before = list_begin(&(a_before->semaphore.waiters));

	struct thread * c = list_entry(b,struct thread,elem);
	struct thread * c_before = list_entry(b_before,struct thread,elem);

	// return 
	// char* a = list_entry(list_begin(&(list_entry(e,struct semaphore_elem,elem)->semaphore.waiters)),struct thread,elem)->name;
	// char* b = list_entry(list_begin(&(list_entry(before,struct semaphore_elem,elem)->semaphore.waiters)),struct thread,elem)->name;
	// printf("%s", list_entry(list_begin(&(list_entry(e,struct semaphore_elem,elem)->semaphore.waiters)),struct thread,elem)->name);
	return c->priority > c_before->priority;
}

void
sema_init (struct semaphore *sema, unsigned value) {
	ASSERT (sema != NULL);

	sema->value = value;
	list_init (&sema->waiters);
}

/* Down or "P" operation on a semaphore.  Waits for SEMA's value
   to become positive and then atomically decrements it.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but if it sleeps then the next scheduled
   thread will probably turn interrupts back on. This is
   sema_down function. */
void
sema_down (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);
	ASSERT (!intr_context ());

	old_level = intr_disable ();
	while (sema->value == 0) {
		//list_push_back (&sema->waiters, &thread_current ()->elem);
		list_insert_ordered(&sema->waiters,&thread_current() ->elem,comapare_priority,NULL);
		
		thread_block ();
	}
	sema->value--;
	intr_set_level (old_level);
}
/* Down or "P" operation on a semaphore, but only if the
   semaphore is not already 0.  Returns true if the semaphore is
   decremented, false otherwise.

   This function may be called from an interrupt handler. */
bool
sema_try_down (struct semaphore *sema) {
	enum intr_level old_level;
	bool success;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (sema->value > 0)
	{
		sema->value--;
		success = true;
	}
	else
		success = false;
	intr_set_level (old_level);

	return success;
}

/* Up or "V" operation on a semaphore.  Increments SEMA's value
   and wakes up one thread of those waiting for SEMA, if any.

   This function may be called from an interrupt handler. */
void
sema_up (struct semaphore *sema) {
	enum intr_level old_level;

	ASSERT (sema != NULL);

	old_level = intr_disable ();
	if (!list_empty (&sema->waiters)){
		list_sort(&sema->waiters, comapare_priority, NULL);
		thread_unblock (list_entry (list_pop_front (&sema->waiters), struct thread, elem));
	}

	sema->value++;
	thread_test_preemption ();
	intr_set_level (old_level);
}

static void sema_test_helper (void *sema_);

/* Self-test for semaphores that makes control "ping-pong"
   between a pair of threads.  Insert calls to printf() to see
   what's going on. */
void
sema_self_test (void) {
	struct semaphore sema[2];
	int i;

	printf ("Testing semaphores...");
	sema_init (&sema[0], 0);
	sema_init (&sema[1], 0);
	thread_create ("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
	for (i = 0; i < 10; i++)
	{
		sema_up (&sema[0]);
		sema_down (&sema[1]);
	}
	printf ("done.\n");
}

/* Thread function used by sema_self_test(). */
static void
sema_test_helper (void *sema_) {
	struct semaphore *sema = sema_;
	int i;

	for (i = 0; i < 10; i++)
	{
		sema_down (&sema[0]);
		sema_up (&sema[1]);
	}
}

/* Initializes LOCK.  A lock can be held by at most a single
   thread at any given time.  Our locks are not "recursive", that
   is, it is an error for the thread currently holding a lock to
   try to acquire that lock.

   A lock is a specialization of a semaphore with an initial
   value of 1.  The difference between a lock and such a
   semaphore is twofold.  First, a semaphore can have a value
   greater than 1, but a lock can only be owned by a single
   thread at a time.  Second, a semaphore does not have an owner,
   meaning that one thread can "down" the semaphore and then
   another one "up" it, but with a lock the same thread must both
   acquire and release it.  When these restrictions prove
   onerous, it's a good sign that a semaphore should be used,
   instead of a lock. */
void
lock_init (struct lock *lock) {
	ASSERT (lock != NULL);

	lock->holder = NULL;
	sema_init (&lock->semaphore, 1);
}

/* Acquires LOCK, sleeping until it becomes available if
   necessary.  The lock must not already be held by the current
   thread.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
bool
compare_donation_priority (struct list_elem *cur, struct list_elem *before, void *aux)
{
	return list_entry (cur, struct thread, d_elem)->priority > list_entry (before, struct thread, d_elem)->priority;
}
void
lock_acquire (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (!lock_held_by_current_thread (lock));
	struct thread *cur = thread_current();
	if(!thread_mlfqs){
	if(lock->holder){ 
		// if(lock->holder->priority > cur->priority){ // lock->holder와 현재 스레드간의 priority 비교는 필수인지
		// }
		cur->wait_on_lock = lock;
		list_insert_ordered(&lock->holder->donations, &cur->d_elem, compare_donation_priority, NULL);
		//list_insert_ordered(&(thread_current()->wait_on_lock->holder->donations), &(thread_current()->d_elem),compare_donation_priority,NULL);
		
		// while(cur->wait_on_lock){ // wait_on_lock이 존재한다면,
		// 	cur->wait_on_lock->holder->priority = cur->priority;
		// 	cur = cur->wait_on_lock->holder;
		// }
		struct thread *start = thread_current();
		while(start->wait_on_lock){ // wait_on_lock이 존재한다면 재귀 수행 -> nested donation!
			struct thread *holder = start->wait_on_lock->holder;
			holder->priority = start->priority;
			start = holder;
		}
	}
	}
	sema_down (&lock->semaphore);
	lock->holder = cur;
	cur->wait_on_lock = NULL;
}

/* Tries to acquires LOCK and returns true if successful or false
   on failure.  The lock must not already be held by the current
   thread.

   This function will not sleep, so it may be called within an
   interrupt handler. */
bool
lock_try_acquire (struct lock *lock) {
	bool success;

	ASSERT (lock != NULL);
	ASSERT (!lock_held_by_current_thread (lock));

	success = sema_try_down (&lock->semaphore);
	if (success)
		lock->holder = thread_current ();
	return success;
}

/* Releases LOCK, which must be owned by the current thread.
   This is lock_release function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to release a lock within an interrupt
   handler. */
void
lock_release (struct lock *lock) {
	ASSERT (lock != NULL);
	ASSERT (lock_held_by_current_thread (lock));
	
	//if(thread_current()->original_priority != thread_get_priority) thread_set_priority(thread_current()->original_priority);
	
	if(!thread_mlfqs){
	struct list_elem *e;
	thread_current()->priority = thread_current()->original_priority;
	
	for (e = list_begin (&thread_current()->donations); e != list_end (&thread_current()->donations); e = list_next (e)){
		// if(list_entry(e,struct thread, d_elem)->wait_on_lock == lock){
		// 	//list_remove(&e);
		// 	list_remove(&list_entry(e,struct thread,d_elem)->d_elem);
		// }
		struct thread *temp = list_entry (e, struct thread, d_elem);
		if (temp->wait_on_lock == lock)
			list_remove (&temp->d_elem);
	}
    struct thread *cur = thread_current ();
	cur->priority = cur->original_priority;

	// donations 중 맥스값과 오리지널 값 비교후 최대값 설정
	if(!list_empty(&cur->donations)){
		struct thread* max_thread = list_entry(list_max(&cur->donations,compare_donation_priority,NULL),struct thread,d_elem);
		cur->priority = MAX(cur->priority,max_thread->priority);
	}
	}

	// if (!list_empty (&cur->donations)) {
	// 	list_sort (&cur->donations, compare_donation_priority,NULL);

    // 	struct thread *front = list_entry (list_front (&cur->donations), struct thread, d_elem);
	// 	if (front->priority > cur->priority)
	// 		cur->priority = front->priority;
    // }

	lock->holder = NULL;
	sema_up (&lock->semaphore);
}

/* Returns true if the current thread holds LOCK, false
   otherwise.  (Note that testing whether some other thread holds
   a lock would be racy.) */
bool
lock_held_by_current_thread (const struct lock *lock) {
	ASSERT (lock != NULL);

	return lock->holder == thread_current ();
}

/* One semaphore in a list. */
// struct semaphore_elem {
// 	struct list_elem elem;              /* List element. */
// 	struct semaphore semaphore;         /* This semaphore. */
// };

/* Initializes condition variable COND.  A condition variable
   allows one piece of code to signal a condition and cooperating
   code to receive the signal and act upon it. */
void
cond_init (struct condition *cond) {
	ASSERT (cond != NULL);

	list_init (&cond->waiters);
}

/* Atomically releases LOCK and waits for COND to be signaled by
   some other piece of code.  After COND is signaled, LOCK is
   reacquired before returning.  LOCK must be held before calling
   this function.

   The monitor implemented by this function is "Mesa" style, not
   "Hoare" style, that is, sending and receiving a signal are not
   an atomic operation.  Thus, typically the caller must recheck
   the condition after the wait completes and, if necessary, wait
   again.

   A given condition variable is associated with only a single
   lock, but one lock may be associated with any number of
   condition variables.  That is, there is a one-to-many mapping
   from locks to condition variables.

   This function may sleep, so it must not be called within an
   interrupt handler.  This function may be called with
   interrupts disabled, but interrupts will be turned back on if
   we need to sleep. */
void
cond_wait (struct condition *cond, struct lock *lock) {
	struct semaphore_elem waiter;

	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	sema_init (&waiter.semaphore, 0);
	//list_push_back (&cond->waiters, &waiter.elem);
	list_insert_ordered(&cond->waiters,&waiter.elem,cmp_sema_priority,NULL);
	// if(thread_current() != (struct thread *)list_begin(&cond->waiters)) thread_yield();
	lock_release (lock);
	sema_down (&waiter.semaphore);
	lock_acquire (lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_signal (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);
	ASSERT (!intr_context ());
	ASSERT (lock_held_by_current_thread (lock));

	struct list_elem* e;
	
	// for (e = list_begin (&cond->waiters); e != list_end (&cond->waiters); e = list_next (e)){

	// 	printf("%s:%d   ",list_entry(list_begin(&(list_entry(e,struct semaphore_elem,elem)->semaphore.waiters)),struct thread,elem)->name,list_entry(e,struct thread,elem)->priority);
	
	// }
	// printf("\n");
	// printf("cur thread: %s\n",thread_current()->name);
	if (!list_empty (&cond->waiters)){
		list_sort(&cond->waiters,cmp_sema_priority,NULL);
		sema_up (&list_entry (list_pop_front (&cond->waiters),
					struct semaphore_elem, elem)->semaphore);
	}
	// if ( thread_current() == list_begin(&lock->semaphore.waiters)){
	// 	return; //thread_yield();
	// } else thread_yield();
}

/* Wakes up all threads, if any, waiting on COND (protected by
   LOCK).  LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */
void
cond_broadcast (struct condition *cond, struct lock *lock) {
	ASSERT (cond != NULL);
	ASSERT (lock != NULL);

	while (!list_empty (&cond->waiters))
		cond_signal (cond, lock);
}
