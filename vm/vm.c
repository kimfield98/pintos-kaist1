/* vm.c: Generic interface for virtual memory objects. */

#include <hash.h>
#include "threads/malloc.h"
#include "vm/vm.h"
#include "vm/inspect.h"
#include "threads/vaddr.h"

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
	struct page page;
	/* TODO: Fill this function. */
	va = pg_round_down(va);
	page.va = va; 

	ASSERT(spt && va)

	struct hash_elem *e = hash_find(&spt->hash_table, &page.h_elem);
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
vm_stack_growth (void *addr UNUSED) {
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
	/* TODO: Validate the fault */
	/* TODO: Your code goes here */
	
	page = spt_find_page(spt,pg_round_down(addr));

	if(page == NULL){
		return false;
	}

	return vm_do_claim_page (page);
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
	pml4_set_page(curr->pml4,page->va,frame->kva,true);

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
}

/* Free the resource hold by the supplemental page table */
void
supplemental_page_table_kill (struct supplemental_page_table *spt UNUSED) {
	/* TODO: Destroy all the supplemental_page_table hold by thread and
	 * TODO: writeback all the modified contents to the storage. */
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