/* file.c: Implementation of memory backed file object (mmaped object). */

#include "vm/vm.h"
#include "threads/vaddr.h"

static bool file_backed_swap_in (struct page *page, void *kva);
static bool file_backed_swap_out (struct page *page);
static void file_backed_destroy (struct page *page);

/* DO NOT MODIFY this struct */
static const struct page_operations file_ops = {
	.swap_in = file_backed_swap_in,
	.swap_out = file_backed_swap_out,
	.destroy = file_backed_destroy,
	.type = VM_FILE,
};

/* The initializer of file vm */
void
vm_file_init (void) {
}

/* Initialize the file backed page */
bool
file_backed_initializer (struct page *page, enum vm_type type, void *kva) {
	/* Set up the handler */
	page->operations = &file_ops;

	struct file_page *file_page = &page->file;
}

/* Swap in the page by read contents from the file. */
static bool
file_backed_swap_in (struct page *page, void *kva) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Swap out the page by writeback contents to the file. */
static bool
file_backed_swap_out (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

/* Destory the file backed page. PAGE will be freed by the caller. */
static void
file_backed_destroy (struct page *page) {
	struct file_page *file_page UNUSED = &page->file;
}

void lazy_mmap (struct page *page, void *aux) {
	struct lazy_aux *aux_ = aux;

    struct file *file = aux_->file;
    off_t offset = aux_->offset;
    uint32_t read_bytes = aux_->read_bytes;
	size_t length = aux_->length;
    bool writable = aux_->writable;

	file_seek(file, offset);
	file_read(file, page->frame->kva, read_bytes);
	
	// free(aux_);
	return true;
}

/* Do the mmap */
void *
do_mmap (void *addr, size_t length, int writable, struct file *file, off_t offset) {
	addr = pg_round_down(addr);
	size_t old_length = length;
	void *old_addr = addr;
	while (length > 0)
	{
		size_t read_bytes = length < PGSIZE ? length : PGSIZE;
		struct lazy_aux *aux = malloc(sizeof(struct lazy_aux));
		aux->file = file;
        aux->offset = offset; // read_start
        aux->read_bytes = read_bytes;
        aux->length = old_length;
        aux->writable = writable;

		vm_alloc_page_with_initializer(VM_FILE, addr, writable, lazy_mmap, aux);

		offset += read_bytes; // 어디까지 읽었는지 알려주는 변수
        length -= read_bytes;
		addr += PGSIZE;
	}
	return old_addr;
	
}

/* Do the munmap */
void
do_munmap (void *addr) {

	struct page *page = spt_find_page(&thread_current()->spt, addr);
	// if pml4 is dirty write file again
	// else just make clean
	// make clean... ex) pml4 clean hash delete,,,,,,
	// do on every page 
}
