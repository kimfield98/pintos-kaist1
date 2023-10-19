/* vm.c: Generic interface for virtual memory objects. */

#include <hash.h>
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "include/userprog/process.h"

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
		/* TODO: 페이지를 생성하고 VM 유형에 따라 초기화 프로그램을 가져옵니다.
		   TODO: 그런 다음 "uninit" 페이지 구조체를 uninit_new를 호출하여 생성합니다. uninit_new를 호출한 후에 필드를 수정해야 합니다. */
        struct page *page = calloc(1, sizeof(struct page));
		upage = pg_round_down(upage); // safe bbang
        switch (VM_TYPE(type)) {
            case VM_ANON:
                uninit_new(page, upage, init, type, aux, anon_initializer);
                page->writable = writable; // aux에 있는 걸로도 넘길 수 있을까?
                break;
            case VM_FILE:
                uninit_new(page, upage, init, type, aux, file_backed_initializer);
                page->writable = writable;
                break;
            default:
                break;
        }
		/* TODO: 페이지를 spt에 삽입합니다. */
        if(!spt_insert_page(spt, page)) {
            return false;
        }
        return true;
	}
err:
	return false;
}

/* Find VA from spt and return page. On error, return NULL. */
struct page *
spt_find_page (struct supplemental_page_table *spt UNUSED, void *va UNUSED) {
	struct page *page = NULL;
	/* TODO: Fill this function. */
	page = malloc(sizeof(struct page));
	va = pg_round_down(va);
	page->va = va; 


	struct hash_elem *e = hash_find(&spt->hash_table,&page->h_elem);
	if(e != NULL){
		return hash_entry(e,struct page,h_elem); // h_elem or hash_elem
	}
	return NULL;
}

/* Insert PAGE into spt with validation. */
bool
spt_insert_page (struct supplemental_page_table *spt UNUSED,
		struct page *page UNUSED) {
	int succ = false;
	/* TODO: Fill this function. */
	if(hash_insert(&spt->hash_table, &page->h_elem) == NULL){
		succ = true;
	}else{
		succ = false;
	}
	return succ;
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

	return victim;
}

/* Evict one page and return the corresponding frame.
 * Return NULL on error.*/
static struct frame *
vm_evict_frame (void) {
	struct frame *victim UNUSED = vm_get_victim ();
	/* TODO: swap out the victim and return the evicted frame. */

	return NULL;
}

/* palloc() and get frame. If there is no available page, evict the page
 * and return it. This always return valid address. That is, if the user pool
 * memory is full, this function evicts the frame to get the available memory
 * space.*/
static struct frame *
vm_get_frame (void) {
	struct frame *frame = NULL;
	/* TODO: Fill this function. */
	frame = calloc(1,sizeof(struct frame));
	frame->kva = palloc_get_page(PAL_USER | PAL_ZERO);
	frame->page = NULL;
	ASSERT (frame != NULL);
	ASSERT (frame->page == NULL);
	return frame;
}

/* Growing the stack. */
static void
vm_stack_growth(void *addr UNUSED)
{
    // todo: 스택 크기를 증가시키기 위해 anon page를 하나 이상 할당하여 주어진 주소(addr)가 더 이상 예외 주소(faulted address)가 되지 않도록 합니다.
    // todo: 할당할 때 addr을 PGSIZE로 내림하여 처리
    vm_alloc_page(VM_ANON | VM_MARKER_0, pg_round_down(addr), 1);
}

/* Handle the fault on write_protected page */
static bool
vm_handle_wp (struct page *page UNUSED) {
}

/* Return true on success */
bool
vm_try_handle_fault (struct intr_frame *f UNUSED, void *addr UNUSED,
		bool user UNUSED, bool write UNUSED, bool not_present UNUSED) {
	struct supplemental_page_table *spt UNUSED = &thread_current ()->spt;
	struct page *page = NULL;
	/* TODO: Your code goes here */

	if(addr == NULL){
		return false;
	}

	if (is_kernel_vaddr(addr))
        return false;

	if (not_present) // 접근한 메모리의 physical page가 존재하지 않은 경우
    {
		/* TODO: Validate the fault */
		// 페이지 폴트가 스택 확장에 대한 유효한 경우인지를 확인한다.
        void *rsp = f->rsp; // user access인 경우 rsp는 유저 stack을 가리킨다.
        if (!user)            // kernel access인 경우 thread에서 rsp를 가져와야 한다.
            rsp = thread_current()->rsp;

        // 스택 확장으로 처리할 수 있는 폴트인 경우, vm_stack_growth를 호출한다.
        if (USER_STACK - (1 << 20) <= rsp - 8 && rsp - 8 == addr && addr <= USER_STACK)
            vm_stack_growth(addr);
        else if (USER_STACK - (1 << 20) <= rsp && rsp <= addr && addr <= USER_STACK)
            vm_stack_growth(addr);

		page = spt_find_page(spt,pg_round_down(addr));
		if(page == NULL)
			return false;
		if (write == 1 && page->writable == 0) // write 불가능한 페이지에 write 요청한 경우
			return false;
		return vm_do_claim_page (page);
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
	va = pg_round_down(va);
	vm_alloc_page(VM_ANON, va, true);
	page = spt_find_page(&thread_current()->spt, va);
	return vm_do_claim_page (page);
}

/* Claim the PAGE and set up the mmu. */
static bool
vm_do_claim_page (struct page *page) {
	struct frame *frame = vm_get_frame ();
	struct thread *curr = thread_current();
	/* Set links */
	frame->page = page;
	page->frame = frame;

	/* TODO: Insert page table entry to map page's VA to frame's PA. */
	pml4_set_page(curr->pml4,page->va,frame->kva,page->writable);

	return swap_in (page, frame->kva);
}

/* Initialize new supplemental page table */
void
supplemental_page_table_init (struct supplemental_page_table *spt UNUSED) {
	hash_init(&spt->hash_table, page_hash, page_less, NULL);	
}

/* Copy supplemental page table from src to dst */
bool
supplemental_page_table_copy (struct supplemental_page_table *dst UNUSED,
        struct supplemental_page_table *src UNUSED) {
    struct hash_iterator i;
    hash_first (&i, &src->hash_table);
	// src_page 정보
    while (hash_next (&i)) {
        struct page *src_page = hash_entry(hash_cur(&i), struct page, h_elem);
        enum vm_type type = src_page -> operations -> type;
        void *upage = src_page -> va;
        bool writable = src_page -> writable;
        vm_initializer *init = src_page ->uninit.init;
        void *aux = src_page -> uninit.aux;
        // type == uninit 이라면 복사하는 페이지도 uninit
        if (type == VM_UNINIT) {
            // vm_initializer *init = src_page ->uninit.init;
            // void *aux = src_page -> uninit.aux;
            if(!vm_alloc_page_with_initializer (VM_ANON, upage, writable, init, aux))
                return false;
            // continue;
        }
        else{
        //uninit이 아니라면
            if (!vm_alloc_page(type, upage, writable)) {
                // init이랑 aux는 Lazy Loading에 필요함
                // 지금 만드는 페이지는 기다리지 않고 바로 내용을 넣어줄 것이므로 필요 없음
                return false;
            }
            //vm_claim_page로 요청한 후 매핑 + 페이지 타입에 맞게 초기화
            if (!vm_claim_page(upage)) {
                return false;
            }
            struct page *dst_page = spt_find_page(dst, upage);
            memcpy(dst_page->frame->kva, src_page->frame->kva, PGSIZE);
        }
    }
    return true;
}

void hash_page_destroy(struct hash_elem *e, void *aux)
{
    struct page *page = hash_entry(e, struct page, h_elem);
    hash_delete(&thread_current()->spt, &page->h_elem);
	destroy(page);
    free(page);
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
	hash_clear(&spt->hash_table, hash_page_destroy); // 해시 테이블의 모든 요소를 제거
}

/* Returns a hash value for page p. */
/* page를 해싱하는 함수  */
unsigned
page_hash (const struct hash_elem *p_, void *aux UNUSED) {
  const struct page *p = hash_entry (p_, struct page, h_elem);
  return hash_bytes(&p->va, sizeof p->va);
}

/* Returns true if page a precedes page b. */
/* hash table 내에서 h_elem을 비교하는 함수 */
bool
page_less (const struct hash_elem *a_,
           const struct hash_elem *b_, void *aux UNUSED) {
  const struct page *a = hash_entry (a_, struct page, h_elem);
  const struct page *b = hash_entry (b_, struct page, h_elem);

  return (uint64_t)a->va < (uint64_t)b->va;
}