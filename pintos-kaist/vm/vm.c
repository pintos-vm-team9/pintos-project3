/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"

static void spt_destroy (struct hash_elem *e, void *aux UNUSED);

/* Initializes the virtual memory subsystem by invoking each subsystem's
 * intialize codes. */
void
vm_init (void) {
	vm_anon_init ();
	vm_file_init ();
#ifdef EFILESYS  /* For project 4 */
	pagecache_init ();
#endif
	register_inspect_intr ();
	/* DO NOT MODIFY UPPER LINES. */
	/* TODO: Your code goes here. */
}

/* Get the type of the page. This function is useful if you want to know the
 * type of the page after it will be initialized.
 * This function is fully implemented now. */
enum vm_type
page_get_type (struct page *page) {
	int ty = VM_TYPE (page->operations->type);
	switch (ty) {
		case VM_UNINIT:
			return VM_TYPE (page->uninit.type);
		default:
			return ty;
	}
}

/* Helpers */
static struct frame *vm_get_victim (void);
static bool vm_do_claim_page (struct page *page);
static struct frame *vm_evict_frame (void);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *tmp_page = (struct page *)malloc(sizeof(struct page));
		// struct page *tmp_page;
		 
		switch(VM_TYPE(type)){
			case VM_ANON:
				// printf("VM_ANON\n");
				uninit_new(tmp_page, upage, init, type, aux, anon_initializer);
				break;
			case VM_FILE:
				// printf("VM_FILE\n");
				uninit_new(tmp_page, upage, init, type, aux, file_backed_initializer);
				break;
			default:
				free(tmp_page);
				NOT_REACHED();
				break;
		}

		/* TODO: Insert the page into the spt. */
		tmp_page->writable = writable;
		return spt_insert_page(spt, tmp_page);
		// uninit_initialize는 in uninit.c와  vm_anon_init,anon_initializer 를 수정해야 할수도 있음 in anon.c
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
    /* 
    위의 함수는 인자로 넘겨진 보조 페이지 테이블에서로부터 가상 주소(va)와 
    대응되는 페이지 구조체를 찾아서 반환합니다. 실패했을 경우 NULL를 반환합니다.
    */    
   	// printf("spt_find_page\n");
    struct page *page = NULL;

    struct page *tmp_page = (struct page *)malloc(sizeof(struct page));
	// struct page *tmp_page;

    if (tmp_page == NULL)
        return NULL;

    tmp_page->va = pg_round_down (va);
    struct hash_elem *target_hash_elem = hash_find(&spt->hash_table, &tmp_page->page_elem);

    if (target_hash_elem == NULL)
        return NULL;

    page = hash_entry(target_hash_elem, struct page, page_elem);

    free(tmp_page);

    return page;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	/* 
	위의 함수는 인자로 주어진 보조 페이지 테이블에 페이지 구조체를 삽입합니다.
	이 함수에서 주어진 보충 테이블에서 가상 주소가 존재하지 않는지 검사해야 합니다.
	*/
	return insert_page_bool(&spt->hash_table, page);
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

struct list_elem* start;
struct list frame_table;

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) { 
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	// + project 3 +
    struct thread *curr = thread_current();
    struct list_elem *e = start;

    for(start = e; start != list_end(&frame_table); start = list_next(start)){
        victim = list_entry(start, struct frame, frame_elem);
        if (pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed(curr->pml4, victim->page->va,0);
        else
            return victim;
    }
    for(start = list_begin(&frame_table); start != e; start = list_next(start)){
        victim = list_entry(start, struct frame, frame_elem);
        if(pml4_is_accessed(curr->pml4, victim->page->va))
            pml4_set_accessed(curr->pml4, victim->page->va, 0);
        else
            return victim;
    }

    return victim;

}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */
	swap_out(victim->page);
	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame*)malloc(sizeof(struct frame));

	/* TODO: Fill this function. */
	void *physical_address = palloc_get_page (PAL_USER); // 물리주소페이지 할당
	if (physical_address == NULL) {
		return vm_evict_frame();
	}

 	frame->kva = physical_address;
 	frame->page = NULL;

	list_push_back(&frame_table, &frame->frame_elem);

	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// vm_alloc_page(VM_ANON | VM_MARKER_0, addr, true);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {

	// printf("handle_fault\n");
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	
	void * fpage_addr = pg_round_down(addr);

	struct page *page = spt_find_page(spt, fpage_addr);
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	 if(is_kernel_vaddr(addr)){
        return false;
    }

    void *rsp_stack = is_kernel_vaddr(f->rsp) ? thread_current()->rsp_stack : f->rsp;
    if(not_present){
        if(!vm_claim_page(addr)){
            if(rsp_stack - 8 <= addr && USER_STACK - 0x100000 <= addr && addr <= USER_STACK){
                vm_stack_growth(thread_current()->stack - PGSIZE);
                return true;
            }
            return false;
        }
        else
            return true;
    }
    return false;
}

/* Free the page.
 * DO NOT MODIFY THIS FUNCTION. */
void
vm_dealloc_page (struct page *page) {
	destroy (page);
	free (page);
}

/* Claim the page that allocate on VA. */
bool
vm_claim_page (void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function */
	page = spt_find_page(&thread_current()->spt, va);
	if (page == NULL)
		return false;
	
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */

	if(install_page_vm(page->va, frame->kva, page->writable)){
        return swap_in(page, frame->kva);
    }

	return false;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	/* 위의 함수는 보조 페이지 테이블를 초기화합니다. 보조 페이지 테이블를 어떤 자료 구조로
	 구현할지 선택하세요. userprog/process.c의 initd 함수로 새로운 프로세스가 시작하거나
	  process.c의 __do_fork로 자식 프로세스가 생성될 때 위의 함수가 호출됩니다. */
	hash_init (&spt->hash_table, hash, less, NULL);
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) {

	// if (dst == NULL || src == NULL) {
	// 	return false;
	// }

	// // 구조체 자체를 복사
	// memcpy(dst, src, sizeof(struct supplemental_page_table));

	// hash_table을 복사
	// return hash_copy(&dst->hash_table, &src->hash_table);;

	// Project 3.2_anonymous page
	struct hash_iterator i;
	hash_first(&i, &src->hash_table);
	while(hash_next(&i))
	{
		
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, page_elem);

		enum vm_type type = page_get_type(parent_page);
		void *upage = parent_page->va;
		bool writable = parent_page->writable;
		vm_initializer *init = parent_page->uninit.init;
		void* aux = parent_page->uninit.aux;

		if(parent_page->uninit.type & VM_MARKER_0)
		{
			setup_stack(&thread_current()->tf);
		}
		else if(parent_page->operations->type == VM_UNINIT)
		{
			if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
				return false;
		}
		else
		{ // UNIT이 아니면 spt 추가만
			if(!vm_alloc_page(type,upage, writable))
				return false;
			if(!vm_claim_page(upage))
				return false;
		}
		if(parent_page->operations->type != VM_UNINIT)
		{
			struct page* child_page = spt_find_page(dst,upage);
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE);
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	struct hash_iterator i;
	hash_first(&i, &spt->hash_table);
	while(hash_next(&i))
	{
		struct page *page = hash_entry(hash_cur(&i), struct page, page_elem);
		if(page->operations->type == VM_FILE)
		{
			do_munmap(page->va);
		}
	}
	hash_destroy(&spt->hash_table, spt_destroy);
}

static void
spt_destroy (struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry (e, struct page, page_elem);
	// destroy (page);
	free (page);
}

uint64_t hash (const struct hash_elem *h_elem, void *aux UNUSED){
	const struct page *page = hash_entry( h_elem, struct page, page_elem);

	return hash_int(page->va);
}

bool less (const struct hash_elem *a, const struct hash_elem *b, void *aux){

	struct page *page_a = hash_entry(a, struct page, page_elem);
	struct page *page_b = hash_entry(b, struct page, page_elem);

	return page_a->va < page_b->va;
}

bool insert_page_bool(struct hash *hash_table, struct page *p){
    if(!hash_insert(hash_table, &p->page_elem))
        return true;
    else
        return false;
}
bool delete_page_bool(struct hash *hash_table, struct page *p){
    if(!hash_delete(hash_table, &p->page_elem))
        return true;
    else
        return false;
}