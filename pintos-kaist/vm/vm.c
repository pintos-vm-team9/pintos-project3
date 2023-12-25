/* vm.c: Generic interface for virtual memory objects. */

#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "userprog/process.h"

struct list frame_table;
struct list_elem *start;

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
	list_init(&frame_table);
	start = list_begin(&frame_table);
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

//project3 추가
static void spt_destroy(struct hash_elem *e, void *aux UNUSED);

/* Create the pending page object with initializer. If you want to create a
 * page, do not create it directly and make it through this function or
 * `vm_alloc_page`. */
/* type: 할당할 페이지 유형, upage: 가상 주소 공간에서 할당할 페이지 시작 주소, writable : 페이지 쓰기 가능 여부, 
init: 페이지 초기화 함수, aux : 초기화 함수에 전달할 추가 데이터*/
bool
vm_alloc_page_with_initializer (enum vm_type type, void *upage, bool writable,
		vm_initializer *init, void *aux) {

	ASSERT (VM_TYPE(type) != VM_UNINIT)

	struct supplemental_page_table *spt = &thread_current ()->spt;

	/* Check wheter the upage is already occupied or not. */
	if (spt_find_page (spt, upage) == NULL) {
		// 유저 페이지가 아직 없으니까 초기화를 해줘야 한다!
		/* TODO: Create the page, fetch the initialier according to the VM type,
		 * TODO: and then create "uninit" page struct by calling uninit_new. You
		 * TODO: should modify the field after calling the uninit_new. */
		struct page *page = (struct page *)malloc(sizeof(struct page));
	
	typedef bool (*initializerFunc)(struct page *, enum vm_type, void *);
	initializerFunc initializer = NULL;

	switch(VM_TYPE(type)){
		case VM_ANON:
			initializer = anon_initializer;
			break;
		case VM_FILE:
			initializer = file_backed_initializer;
			break;
			}
	uninit_new(page, upage, init, type, aux, initializer);

	// page member 초기화
	page->writable = writable;
	/* TODO: Insert the page into the spt. */
	return spt_insert_page(spt, page);
	
	}
err:
	return false;
}


/* Find VA from spt and return page. On error, return NULL. */
/* 보조 페이지 테이블(spt)에서 주어진 가상 주소(va)에  해당하는 페이지를 찾아 반환하는 함수 */
struct page *
spt_find_page (struct supplemental_page_table *spt, void *va) {
	// struct page *page = NULL;
	/* TODO: Fill this function. */
    // struct page dummy_page; // 해싱을 위해 더미 페이지를 생성하고
	// dummy_page->va = pg_round_down(va); //이 페이지의 va를 페이지 크기로 내림하여 설정
    // struct hash_elem *e;

    // e = hash_find(&spt->swap_pages_table, &dummy_page.h_elem); //spt의 해시 테이블에서 더미 페이지에 해당하는 요소를 찾아 반환

	// if(e == NULL) //테이블에서 페이지를 못찾았으면 NULL 반환
	// 	return NULL;

    // return page = hash_entry(e, struct page, h_elem); //찾은 경우 hash_entry 함수를 사용하여 해시 요소로부터 페이지 구조체에 대한 포인터를 추출해 반환

	struct page *page = malloc(sizeof(struct page));
	/* TODO: Fill this function. */
	struct hash_elem *e;

	page->va = pg_round_down(va);
	e = hash_find(&spt->swap_pages_table, &page->h_elem);
	free(page);
	return e != NULL ? hash_entry (e, struct page, h_elem) : NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if(spt != NULL && page != NULL){
		// hash_insert (struct hash *h, struct hash_elem *new)
		if(!hash_insert(&spt->swap_pages_table, &page->h_elem)){ //null이면 삽입 성공
			succ = true;
		}
	}
	return succ;
}

bool spt_delete_page(struct hash *pages, struct page *p){
	if(hash_delete(pages, &p->h_elem))
		return false;
	else return true;
}

void
spt_remove_page (struct supplemental_page_table *spt, struct page *page) {
	vm_dealloc_page (page);
	return true;
}

/* Get the struct frame, that will be evicted. */
static struct frame *
vm_get_victim (void) {
	struct frame *victim = NULL;
	 /* TODO: The policy for eviction is up to you. */
	struct thread *curr = thread_current();
	struct list_elem *e, *start;

	//lru 방식
	for (start = e; start != list_end(&frame_table); start = list_next(start)) {
		victim = list_entry(start, struct frame, f_elem);
		if (pml4_is_accessed(curr->pml4, victim->page->va))
			pml4_set_accessed(curr->pml4, victim->page->va, 0);
		else
			return victim;
	}

	for (start = list_begin(&frame_table); start != e; start = list_next(start)) {
		victim = list_entry(start, struct frame, f_elem);
		if (pml4_is_accessed(curr->pml4, victim->page->va))
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

	if(victim->page != NULL)
		swap_out(victim->page); //swap_out으로 제거

	return victim;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
/* palloc()을 호출하고 프레임을 가져옵니다. 사용 가능한 페이지가 없으면 페이지를 퇴거하고 반환합니다. 이 함수는 항상 유효한 주소를 반환합니다. 
즉, 사용자 풀 메모리가 가득 차면 이 함수는 프레임을 퇴거시켜 사용 가능한 메모리 공간을 확보합니다.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = (struct frame *)malloc(sizeof(struct frame));
	/* TODO: Fill this function. */
	
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	frame->kva = palloc_get_page(PAL_USER); // user pool에서 커널 가상 주소 공간으로 1page 할당
	if (frame->kva == NULL) { // 유저 풀 공간이 하나도 없다면
		frame = vm_evict_frame(); // frame에서 공간 내리고 새로 할당받아온다.
		frame->page = NULL;
		return frame;
	}
	list_push_back(&frame_table, &frame->f_elem);
	frame->page = NULL;
	return frame;

}

/* Growing the stack. */
static void
vm_stack_growth (void *addr UNUSED) {
	// Project 3.3_stack growth
	void *stack_bottom = pg_round_down (addr);
	size_t req_stack_size = USER_STACK - (uintptr_t)stack_bottom;
	if (req_stack_size > (1 << 20)) PANIC("Stack limit exceeded!\n"); // 1MB

	//Alloc page from tested region to previous claimed stack page.
	void *growing_stack_bottom = stack_bottom;
	while ((uintptr_t) growing_stack_bottom < USER_STACK &&
		vm_alloc_page (VM_ANON | VM_MARKER_0, growing_stack_bottom, true)) { // VM_MARKER_0 스탐은 STACK으로 함
		growing_stack_bottom += PGSIZE;
	};
	vm_claim_page(stack_bottom); // Lazy load requested stack page only

	// Project 3.3_end
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
// 이 함수는 유효한 페이지 폴트인지를 우선 검사
// 물리 메모리와 매핑은 되어 있지만 콘텐츠가 로드되어 있지 않은 경우- bogus fault- 라면  콘텐츠를 로드하면 되고, 
// 매핑되지 않은 페이지라면 그대로 유효한 페이지 폴트라는 의미인 것 같습니다.
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */

	if(is_kernel_vaddr(addr))
	{
		return false;
	}

	if (not_present){
		if(!vm_claim_page(addr))
		{
			return false;
		}
		else
			return true;
	}
	return false;

	// return vm_do_claim_page (page);
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
	struct thread *cur = thread_current();
	struct page *page = NULL;
	/* TODO: Fill this function */
	//spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED)
	page = spt_find_page(&cur->spt, va);
	if(page==NULL)
		return false;

	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct thread *cur = thread_current();
	struct frame *frame = vm_get_frame ();

	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	//pml4_get_page (uint64_t *pml4, const void *uaddr) : 주어진 사용자 주소에 매핑된 페이지가 없으면 NULL을 반환
	//pml4_set_page (uint64_t *pml4, void *upage, void *kpage, bool rw) : 사용자 가상 주소에 물리 페이지 프레임 매핑이 성공했는지 안했는지
	if(pml4_get_page(cur->pml4, page->va)==NULL && pml4_set_page(cur->pml4, page->va, frame->kva, page->writable))
		return swap_in (page, frame->kva); //해당 사용자 주소에 매핑된 페이지가 없고, 사용자 주소에 물리 페이지 프레임 매핑을 성공 했다면 
		//swap_in(page, frame->kva) : page를 메모리로 가져오는 역할
	
	return false;
}

unsigned
page_hash(const struct hash_elem *p_, void *aux UNUSED)
{
	const struct page *p = hash_entry(p_, struct page, h_elem);
	return hash_bytes(&p->va, sizeof p->va);
}
bool page_less(const struct hash_elem *a_,
			   const struct hash_elem *b_, void *aux UNUSED)
{
	const struct page *a = hash_entry(a_, struct page, h_elem);
	const struct page *b = hash_entry(b_, struct page, h_elem);

	return a->va < b->va;
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) { //project 3 구현
	//struct hash page_table = malloc(sizeof(struct hash));
	//bool hash_init (struct hash *h,hash_hash_func *hash, hash_less_func *less, void *aux)
	hash_init(&spt->swap_pages_table, page_hash, page_less, NULL);
	//spt->swap_pages_table = page_table;
}

/* Copy supplemental page table from src to dst */
//보조 페이지 테이블 src를 dst로 복사하는 함수
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
		struct supplemental_page_table *src UNUSED) { //project 3 구현
	struct hash_iterator i;
	hash_first(&i, &src->swap_pages_table);
	while(hash_next(&i)) //hase table을 순회하면서 각 페이지를 처리
	{
		struct page *parent_page = hash_entry(hash_cur(&i), struct page, h_elem); //page 정보 확인

		enum vm_type type = page_get_type(parent_page); //page 타입
		void *upage = parent_page->va; //page va
		bool writable = parent_page->writable; //page writable
		vm_initializer *init = parent_page->uninit.init;
		void *aux = parent_page->uninit.aux;

		if(parent_page->uninit.type & VM_MARKER_0){ //
			setup_stack(&thread_current()->tf); // 다른 파일에서 사용하려면 함수 선언할때 static 빼야함
			//스택 설정 // vm_marker_0 유형은 스택을 포함하는 페이지여서, 스택 포인터와 프레임 포인터를 초기화하여 스택을 사용할 수 있도록 준비하는 역할
		}
		else if(parent_page->operations->type == VM_UNINIT){ //페이지를 할당하고 초기화
			if(!vm_alloc_page_with_initializer(type, upage, writable, init, aux))
				return false;
		}else{ //그 외 유형
			if(!vm_alloc_page(type, upage, writable)) //페이지 할당
				return false;
			if(!vm_claim_page(upage)) //페이지 소유권 주장
				return false;
		}

		if(parent_page->operations->type != VM_UNINIT){ //page가 초기화된 유형이 아닌 경우
			struct page * child_page = spt_find_page(dst, upage); //dst에서 해당 페이지를 찾아
			memcpy(child_page->frame->kva, parent_page->frame->kva, PGSIZE); //페이지 내용을 복사해옴
		}
	}
	return true;
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) { //project 3 구현
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */

	struct hash_iterator i;
	hash_first(&i, &spt->swap_pages_table);
	while(hash_next(&i)){
		struct page *page = hash_entry(hash_cur(&i), struct page, h_elem);
		if(page->operations->type == VM_FILE){
			do_munmap(page->va);
		}
	}
	hash_destroy(&spt->swap_pages_table, spt_destroy);
}

static void
spt_destroy(struct hash_elem *e, void *aux UNUSED){
	struct page *page = hash_entry(e, struct page, h_elem);
	ASSERT(page != NULL);
	destroy(page);
	free(page);
}

