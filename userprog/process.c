#include "userprog/process.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/mmu.h"
#include "threads/palloc.h"
#include "threads/synch.h" // fd_lock을 스레드마다 구현하기 위함
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/gdt.h"
#include "userprog/syscall.h" // fd_table_destroy를 위한 추가
#include "userprog/tss.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#ifdef VM
#include "vm/vm.h"
#endif

/* 기본적인 함수 Prototype */
static void process_cleanup(void);
static bool load(const char *file_name, struct intr_frame *if_);
static void initd(void *f_name);
static void __do_fork(void *);

/* load가 sync가 맞지 않아서 선언한 전역 세마 */
struct semaphore *load_sema;

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// Process Initiation ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 최초의 유저 프로세스인 initd를 포함한 모든 프로세스를 초기화 하는 공통 함수 */
static void process_init(void) {
    struct thread *current = thread_current();

    /* (중요) PintOS는 켜지는 시점부터 thread에서 시작되기에, 그 child가 생길 가능성을 고려해서 thread.c의 thread_create()에 모든 것을 옮겨둠 */
}

/* 최초의 user-side 프로그램인 initd를 시작하는 함수로, 해당 TID를 반환.
   새로 생성되는 스레드는 이 함수가 종료되기 전에 Schedule 되거나 exit될 수 있음.
   최초의 프로세스를 만드는 함수이기 때문에 Boot 시점에 단 한번만 호출됨. */
tid_t process_create_initd(const char *file_name) {
    char *fn_copy;
    tid_t tid;

    /* fn_copy라는 변수에 file_name을 복사해서 활용.
       caller와 initd 내부의 load()간 race condition 방지 목적 */
    fn_copy = palloc_get_page(0);
    if (fn_copy == NULL)
        return TID_ERROR;
    strlcpy(fn_copy, file_name, PGSIZE);

    /* 스레드 이름 파싱 (테스트 통과용) */
    char *save_ptr;
    strtok_r(file_name, " ", &save_ptr); //파일이름 파싱

    /* file_name을 실행하기 위한 새로운 스레드를 생성 (스레드 이름도 initd) */
    tid = thread_create(file_name, PRI_DEFAULT, initd, fn_copy);
    if (tid == TID_ERROR){
        palloc_free_page(fn_copy);
        return TID_ERROR;
    }
    // palloc_free_page(fn_copy);
    return tid;
}

/* 최초 발생한 유저 프로세스 initd를 시작시키는 함수 (process_exec 호출) */
static void initd(void *f_name) {
#ifdef VM
    supplemental_page_table_init(&thread_current()->spt);
#endif

    process_init();

    if (process_exec(f_name) < 0)
        PANIC("Fail to launch initd\n");
    NOT_REACHED();
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////// Process Fork ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 현재 구동중인 프로세스를 'name'으로 포크하는 함수.
   성공시 새로운 프로세스의 TID를 반환하거나, 실패시 TID_ERROR 반환. */
tid_t process_fork(const char *name, struct intr_frame *if_) {

    /* fork()에서 찍은 tf의 스냅샷을, 현재 스레드의 backup 멤버에게 복사 붙여넣기 */
    struct intr_frame *parent_backup = &thread_current()->tf_backup_fork;
    memcpy(parent_backup, if_, sizeof(struct intr_frame));

    // if (thread_current()->fork_depth >= 30) {
    //     return TID_ERROR;
    // }

    /* 스레드 생성, 리턴되는 pid 값 캡쳐 */
    tid_t pid = thread_create(name, PRI_DEFAULT, __do_fork, thread_current());

    /* 만일 스레드 생성에 실패했다면 ERROR 반환  */
    if (pid == TID_ERROR) {
        return TID_ERROR;
    }

    /* Caller의 fork_sema를 내리면서 대기 상태 진입 ; _do_fork가 끝날때 Callee가 sema_up 예정 */
    sema_down(&thread_current()->fork_sema);

    return pid;
}

#ifndef VM // duplicate_pte()는 VM으로 Define 되지 않았을 경우에만 참고되는 함수

/* Parent의 Address Space를 복제하는 함수 (Project 2에서만 사용).
   pml4_for_each() 함수에 Parameter로 넣어야 함. */
static bool duplicate_pte(uint64_t *pte, void *va, void *aux) {
    struct thread *current = thread_current();
    struct thread *parent = (struct thread *)aux;
    void *parent_page;
    void *newpage;
    bool writable;

    /* _do_fork()에서 pml4_for_each()로 모든 parent의 페이지테이블 entry에 duplicate_pte를 적용함 */
    /* 단, 커널 영역의 페이지테이블은 건드리면 안되니 (1)번으로 방지 필요 */

    /* (1) 만일 parent_page가 커널 영역이라면 바로 true 반환 */
    if (is_kernel_vaddr(va))
        return true;

    /* (2) duplicate_pte()는 각각의 페이지테이블 entry에 적용 ; 우선 부모 역할의 페이지를 포인터로 확보 */
    parent_page = pml4_get_page(parent->pml4, va);

    /* (3) 새로운 페이지를 선언 및 유저 영역에 NULL-init된 메모리 할당 (페이지 할당) */
    newpage = palloc_get_page(PAL_USER);
    if (!newpage)
        return false;

    /* (4) parent_page를 newpage로 복제 */
    memcpy(newpage, parent_page, PGSIZE);
    writable = (*pte & PTE_W) ? true : false;
    // writeable... 이부분이 GPT 도움 받은 부분 ; 부모의 각 페이지가 writeable 한지 확인하고 해당 값도 넘겨주는 과정
    // PTE_W는 페이지테이블의 각 엔트리별 lower bit flag로, write 권한이 있는지 확인하는 마크로
    // Parameter로 전달받은 부모의 pml4 엔트리, 그 PTE_W flag 값이 True/ false 인지 저장하고 set_page()에서 적용

    /* (5) pml4_set_page로 child의 페이지테이블에 새로운 페이지를 추가/설정 (주소 va에 writeable 권한 제공) */
    if (!pml4_set_page(current->pml4, va, newpage, writable)) {

        /* (6) 만일 page insert가 실패한다면 에러 처리 필요 */
        palloc_free_page(newpage);
        return false;
    }

    return true;
}

#endif

/* 스레드 Function으로, 부모의 Execution Context를 복사하는 함수. */
static void __do_fork(void *aux) {
    struct intr_frame child_if_;
    struct thread *parent = (struct thread *)aux;
    struct thread *current = thread_current();

    /* 앞선 process_fork에서 복사해둔 thread_current의 backup에 접속 */
    struct intr_frame *parent_if = &parent->tf_backup_fork;
    bool succ = true;

    /* (1) 백업된 intr_frame의 데이터를 복사 */
    memcpy(&child_if_, parent_if, sizeof(struct intr_frame));

    /* (2) 페이지테이블을 복사 */
    current->pml4 = pml4_create();
    if (current->pml4 == NULL)
        goto error;

    process_activate(current);
#ifdef VM
    supplemental_page_table_init(&current->spt);
    if (!supplemental_page_table_copy(&current->spt, &parent->spt))
        goto error;
#else
    if (!pml4_for_each(parent->pml4, duplicate_pte, parent)) // 유저 커널 공간의 모든 pte entry에 duplicate_pte(parent)를 적용하는 함수 ; 성공시 true 반환
        goto error;
#endif

    /* (3) File Descriptor를 복사 ; thread_create에서 palloc은 완료 */
    lock_acquire(&parent->fd_lock);
    for (int i = 2; i < 256; i++) {
        if (parent->fd_table[i] != 0) {
            current->fd_table[i] = file_duplicate(parent->fd_table[i]);
        } else {
            current->fd_table[i] = 0;
        }
    }
    lock_release(&parent->fd_lock);

    /* (4) 새로 생성되는 프로세스와 관련된 초기화 작업 수행 */
    process_init();

    /* (5) 부모의 Children 리스트에 자식의 child_elem을 넣고, child의 부모 포인터를 업데이트하고, sema_up으로 포크가 완료됨을 통보 */
    current->parent_is = parent; // thread_create()시점에 정의하긴 했으나, fork caller가 맞도록 다시 재확인
    sema_up(&parent->fork_sema);

    /* 최종적으로 완성된 child process로 switch 하는 과정 ; 단, fork된 child는 parent의 fork()에서 사용된 R.rax 값이 비어야 함 */
    if (succ) {
        child_if_.R.rax = 0;
        do_iret(&child_if_);
    }
error:
    sema_up(&parent->fork_sema);
    exit(-1);
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// Process Execution ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* f_name을 새로 생성된 프로세스/스레드 내에서 실행하기 위한 함수.
   여기서 f_name은 전체 커맨드라인으로, argc-argv 파싱이 필요함.
   함수 실행 실패 시 -1을 반환.
   ("Switch the current execution context to the f_name") */
int process_exec(void *f_name) {

    bool success;
    char *file_name = (char *)f_name;

    /* 현재 스레드의 intr_frame을 사용하면 안됨.
       해당 intr_frame에 값을 저장하는 것은 스케쥴러의 역할 (reschedule 시점).
       여기서는 임시로 새로운 intr_frame 변수를 선언/초기화 한 뒤에 파일을 load()할 때 사용. */
    struct intr_frame _if;

    /* Segment Selector는 특정 메모리 Segment를 정의하고 접근하기 위해서 활용되는 일종의 Descriptor.
       해당 세그먼트의 특징 (base address, limit, access rights등) 을 담고 있음.
       최근에는 Segmented Memory 모델이 아닌 Paging 기반의 Flat Memory Model로 바뀌었는데,
       x86 아키텍쳐가 Segementation을 기반으로 개발되었기 때문에 남아있는 일부 레거시 Segment Selector 들이 있음.
       대표적인게 ES, SS인데, PintOS에서는 다른 용도가 있을 수 있으니 주의깊게 살펴볼 것. */
    _if.ds = _if.es = _if.ss = SEL_UDSEG; // User Data, Extra, Stack Segment Selector를 User Data Segment로 초기화
    _if.cs = SEL_UCSEG;                   // User Code Segment Selector를 User Code Segment로 초기화
    _if.eflags = FLAG_IF | FLAG_MBS;      // EFLAGS 레지스터에 Interrupt를 켜고, 그냥 레거시 지원을 위해서 필요한 MBS 값도 활성화 (Historical Quirk)

    /* 현재 프로세스의 User-side Virtual Memory pml4를 NULL로 처리한 뒤 페이지 테이블 전용 레지스터를 0으로 초기화 (사용 준비) */
    process_cleanup();

    /* 임시로 저장한 intr_frame을 활용해서 파일을 디스크에서 실제로 로딩, 실패시 -1 반환으로 방어.
       load() 함수에서 _if의 값들을 마저 채우고 현재 스레드로 적용함. */

    success = load(file_name, &_if);
    

    palloc_free_page(file_name);
    if (!success)
        return -1;

    /* 새로운 프로세스로 전환해서 작업 시작 */
    do_iret(&_if);
    NOT_REACHED();
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// Process Wait & Exit ///////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* TID로 상징되는 Child Process가 끝나고 exit status로 돌아올 때 까지 대기시키는 함수.
   kernel에 의해서 종료되는 경우 -1을 반환하며,
   TID가 재대로 된 값이 아니거나, caller의 child가 아니거나, process_wait()이 이미 호출 되었어도 -1 반환. */
int process_wait(tid_t child_tid) {

    struct thread *curr = thread_current();
    struct thread *child = NULL;

    /* (1) Parent의 children_list를 탐색해서 제공된 tid 매칭 작업 수행 */
    struct list_elem *e;
    for (e = list_begin(&curr->children_list); e != list_end(&curr->children_list); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, child_elem);
        if (t->tid == child_tid) {
            child = t; // 발견
            break;
        }
    }

    /* (2) 매치가 없다면, 또는 있는데 이미 누군가 wait를 걸었다면, 예외처리. */
    if (!child || child->already_waited) {
        return -1;
    }
    
    // (참고) GPT 리뷰 요청 시, orphaned process도 확인하라 함 (부모가 죽고 자식만 살아있는 경우) ; 일단 스킵

    /* (3) 문제없이 찾았다면 child의 already_waited 태그를 업데이트하고, wait_sema 대기 시작. */
    child->already_waited = true;

    sema_down(&child->wait_sema);

    /* (4) Child가 process_exit에서 시그널을 보냈으니 sema_down(wait_sema)가 통과됨 ; 이제 해당 Child의 exit_status 저장. */
    int return_status = child->exit_status;
    list_remove(&child->child_elem);
    /* (5) sema_down(free_sema)로 기다리고 있는 child (process_exit)에게 시그널 */
    sema_up(&child->free_sema);
    
    /* (6) 이제 없는 자식이니, 호적에서 제거 */
    // list_remove(&child->child_elem);

    /* (7) 최종적으로 return_status 반환 */
    return return_status;
}

/* thread_exit에서 호출되는 함수로, 프로세스를 종료시킴. */
void process_exit(void) {

    struct thread *curr = thread_current();
    struct file **table = curr->fd_table;

    /* Debug */
    if (!curr->parent_is) {
        printf("%s\n", curr->name);
    }


	int cnt = 2;
	while (cnt < 256)
	{
		if (table[cnt])
		{
			file_close(table[cnt]);
			table[cnt] = NULL;
		}
		cnt++;
	}

    if (curr->parent_is) {
        sema_up(&curr->wait_sema);
        sema_down(&curr->free_sema);
    }

    palloc_free_page(table);
    process_cleanup();

}

/* 현재 프로세스의 페이지 테이블 매핑을 초기화하고, 커널 페이지 테이블만 남기는 함수 */
static void process_cleanup(void) {
    struct thread *curr = thread_current();

#ifdef VM
    supplemental_page_table_kill(&curr->spt);
#endif

    /* Struct Thread에 있는, Userprog 전용 멤버.
       Page Map Level 4의 약자이며, Virtual Address를 Physical로 전환하는데 활용 (x86-64).
       각각의 엔트리는 pml4 -> pdpt -> pdt -> pt를 거쳐서 전환됨. */
    uint64_t *pml4;
    pml4 = curr->pml4;

    /* Virtual Memory 공간은 프로세스 고유의 공간과, 모두가 같은 매핑 정보를 갖는 커널-사이드 공간으로 나뉨.
       다음 과정을 통해서 현재 프로세스의 pml4를 삭제하고 Kernel 정보만 남아있는 상태로 전환함 (User-side만 비우는 작업). */
    if (pml4 != NULL) {

        // plm4가 이미 NULL이라면 pml4가 없거나 이미 삭제되었기 때문에 별도의 작업이 필요 없음
        curr->pml4 = NULL;   // 현재 프로세스 (스레드)의 pml4 (User-side Mapping)를 NULL로 바꾸고,
        pml4_activate(NULL); // NULL 값으로 CPU의 Active pml4를 비우는 작업 (Kernel-side는 별도로 그대로 유지됨)
        pml4_destroy(pml4);  // 마지막으로 pml4를 destroy()해서 관련된 메모리 Alloc들을 전부 풀어주는 과정

        /* 위 과정에서 순서가 굉장히 중요함 ; Timer Interrupt가 호출되면서 Context Switch가 발생할 수 있기 때문.
           먼저 NULL로 pml4를 바꿔버려서 OS가 참고할 수 없도록 만드는 Safety Measure.
           이후에 NULL이라는 Parameter를 기반으로 Kernel-side만 초기화 하는 activate() 함수를 실행, 맨 마지막으로 pml4를 삭제해야 함.
           pml4를 삭제하는 과정에서 kernel-side 메모리 접근이 필요할 수 있고, Interrupt를 통해서 계속 해당 스레드가 끊길 수 있기 때문.
           만일 kernel-side를 activate 하지 않고 destroy()로 이동하면 deallocate된 메모리로 접근하며 문제 발생 가능. */
    }
}

////////////////////////////////////////////////////////////////////////////////
/////////////////////////// Process Context Switching //////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* Context Switch 시점에 매번 호출되어야 하는 함수  */
void process_activate(struct thread *next) {

    /* 스레드의 page table을 활성화 */
    pml4_activate(next->pml4);

    /* %rsp를 스레드의 커널 스택 포인터로 이동 */
    tss_update(next);
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// ELF related Macros ////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* We load ELF binaries.  The following definitions are taken
 * from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
#define EI_NIDENT 16

#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
 * This appears at the very beginning of an ELF binary. */
struct ELF64_hdr {
    unsigned char e_ident[EI_NIDENT];
    uint16_t e_type;
    uint16_t e_machine;
    uint32_t e_version;
    uint64_t e_entry;
    uint64_t e_phoff;
    uint64_t e_shoff;
    uint32_t e_flags;
    uint16_t e_ehsize;
    uint16_t e_phentsize;
    uint16_t e_phnum;
    uint16_t e_shentsize;
    uint16_t e_shnum;
    uint16_t e_shstrndx;
};

struct ELF64_PHDR {
    uint32_t p_type;
    uint32_t p_flags;
    uint64_t p_offset;
    uint64_t p_vaddr;
    uint64_t p_paddr;
    uint64_t p_filesz;
    uint64_t p_memsz;
    uint64_t p_align;
};

/* Abbreviations */
#define ELF ELF64_hdr
#define Phdr ELF64_PHDR

////////////////////////////////////////////////////////////////////////////////
////////////////////////// File Load, Stack Setup etc //////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* load() 보조함수 Prototype은 여기서 별도로 선언 */
void parse_argv_to_stack(char **argv, struct intr_frame *if_);
static bool setup_stack(struct intr_frame *if_);
static bool validate_segment(const struct Phdr *, struct file *);
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable);

/* FILE_NAME에서 ELF Executable을 추출, 현재 스레드에 로딩하는 함수.
   %rip 레지스터에 entry point를 저장하고, %rsp에 스택 포인터도 초기화.
   함수 실행 성공시 true를, 아니면 false를 반환 (process_exec에서 'success' 변수에 저장됨). */
static bool load(const char *file_name, struct intr_frame *if_) {

    struct thread *t = thread_current(); // 현재 스레드를 의미하는 포인터 선언 및 초기화
    struct ELF ehdr;                     // 로딩되는 파일의 ELF 헤더 Struct를 선언
    struct file *file = NULL;            // 파일 포인터를 NULL로 초기화
    off_t file_ofs;                      // 파일 내부에서 Offset 역할
    bool success = false;                // ELF 로딩이 성공이라면 true로 바뀜
    int i;                               // 반복문 전용 정수

    /* 새로 로딩되는 파일을 실행하는 스레드, 그 스레드를 위한 pml4 생성 */
    t->pml4 = pml4_create();
    if (t->pml4 == NULL)
        goto done;
    process_activate(t); // 현재 스레드의 pml4를 활성화하고, 스택포인터를 현재 스레드의 커널 스택 위치로 이동

    /* Command Line으로 주어진 내용을 파싱/토큰화 */
    char *argv[100] = {0}; // 배열 전체를 0으로 Initialize
    int argc = 0;
    char *token, *save_ptr;

    for (token = strtok_r(file_name, " ", &save_ptr); token != NULL; token = strtok_r(NULL, " ", &save_ptr)) {
        argv[argc] = token;
        argc++;

        if (argc >= 100) {
            printf("CUSTOM MESSAGE : Too Many Arguments passed to process_exec() for parsing \n");
            break;
        }
    }

    char *parsed_file_name = argv[0];

    /* 실제 Executable File을 로딩 */

    file = filesys_open(parsed_file_name);

    // printf("CUSTOM MESSAGE : file_name : %s\n", parsed_file_name);
    if (file == NULL) {
        printf("load: %s: open failed\n", parsed_file_name);
        goto done;
    }

    /* Executable File의 헤더를 읽고 검증 */
    if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr || memcmp(ehdr.e_ident, "\177ELF\2\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 0x3E // amd64
        || ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Phdr) || ehdr.e_phnum > 1024) {
        printf("load: %s: error loading executable\n", parsed_file_name);
        goto done;
    }

    /* 검증된 헤더 값을 읽어오는 과정 */
    file_ofs = ehdr.e_phoff;
    for (i = 0; i < ehdr.e_phnum; i++) {
        struct Phdr phdr;

        if (file_ofs < 0 || file_ofs > file_length(file))
            goto done;
        file_seek(file, file_ofs);

        if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
            goto done;
        file_ofs += sizeof phdr;
        switch (phdr.p_type) {
        case PT_NULL:
        case PT_NOTE:
        case PT_PHDR:
        case PT_STACK:
        default:
            /* Ignore this segment. */
            break;
        case PT_DYNAMIC:
        case PT_INTERP:
        case PT_SHLIB:
            goto done;
        case PT_LOAD:
            if (validate_segment(&phdr, file)) {
                bool writable = (phdr.p_flags & PF_W) != 0;
                uint64_t file_page = phdr.p_offset & ~PGMASK;
                uint64_t mem_page = phdr.p_vaddr & ~PGMASK;
                uint64_t page_offset = phdr.p_vaddr & PGMASK;
                uint32_t read_bytes, zero_bytes;
                if (phdr.p_filesz > 0) {
                    /* Normal segment.
                     * Read initial part from disk and zero the rest. */
                    read_bytes = page_offset + phdr.p_filesz;
                    zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
                } else {
                    /* Entirely zero.
                     * Don't read anything from disk. */
                    read_bytes = 0;
                    zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
                }
                if (!load_segment(file, file_page, (void *)mem_page, read_bytes, zero_bytes, writable))
                    goto done;
            } else
                goto done;
            break;
        }
    }

    /* if_ 구조체를 위해서 User Stack을 Allocate 한 뒤 %rsp를 업데이트 */
    if (!setup_stack(if_))
        goto done;

    /* if_ 구조체의 instruction pointer가 프로그램의 Entry point를 가리키도록 업데이트 */
    if_->rip = ehdr.e_entry;

    /* 파싱된 나머지 argv, argc 값들을 스택에 추가 (여기서부터 끝까지) */
    parse_argv_to_stack(argv, if_);

    /* 성공했다고 회신 예정이니 값 변경 */
    success = true;

done:
    /* 실행이 끝나고 나면 성공/실패 여부와 무관하게 아래 코드 실행 */
    file_close(file);
    return success;
}

/* load()가 너무 길어서 분리한 보조 함수. */
void parse_argv_to_stack(char **argv, struct intr_frame *if_) {

    int i, j;
    int argc = 0;
    char **temp_argv = argv;

    /* (0) Temp_argv 더블포인터로 argv 이동하되 값을 직접 건드리지 않고 작업 */
    while (*temp_argv) {
        argc++;
        temp_argv++;
    }

    // (1) rsp 스택 포인터를 이동시키는 임시 포인터 선언 ; 현재 intr_frame의 스택 포인터 %rsp를 가리키면서 출발 (rsp 자체가 포인터니까 더블포인터로 구현)
    char **stack_ptr = (char **)if_->rsp;

    // (2) argv에 있는 문자열을 마지막에서 첫번째 순서로 스택에 추가
    for (i = argc - 1; i >= 0; i--) {                     // argc는 argv 배열에 담긴 element의 숫자인데, j는 index 값이니 -1로 조정
        stack_ptr -= strlen(argv[i]) + 1;                 // Null Pointer (\0)를 포함한 만큼 임시 스택 포인터를 아래로 이동 (위에서 시작하니)
        strlcpy(stack_ptr, argv[i], strlen(argv[i]) + 1); // 도달한 임시 포인터 위치에서부터 위로 (주소가 위로 커지니) argv[j] 값을 추가
        argv[i] = stack_ptr; // 실제 argv 배열의 값을 각 시점의 임시 포인터로 변경 (argv 포인터 배열로 만드는 작업 ; (3)에서 스택에 또 추가해야 함)
    }

    // (3) 스택 Alignment 조정 (word-align) ; 8의 배수에 맞춰서 임시 포인터 위치 조정 (0으로 채우기)
    while ((uint64_t)stack_ptr % 8 != 0) {
        stack_ptr--;
        *stack_ptr = 0;
    }

    // (4) 1번에서 argv 배열을 각 요소의 메모리 위치를 가리키는 배열포인터로 전환했으니, 이제 각 값들을 다시 스택에 추가
    stack_ptr -= (argc + 1) * sizeof(char *); // 각 포인터는 char 크기 ; 그만큼 스택 임시포인터 하향 조정 ; argc + 1은 NULL 값을 추가하기 위한 선제 조치
    for (j = 0; j < argc; j++) {              // 이제 반복문으로 argv 포인터 배열의 각 요소들을 stack_ptr에 추가
        stack_ptr[j] = argv[j];               // 공간을 확보한 stack_ptr에서부터 char* 크기만큼 i번 이동, 각 위치에 argv[i]의 포인터를 저장
    }
    stack_ptr[argc] = NULL; // argc가 4라면, argv[4]의 위치에 NULL Terminator를 추가 (x86-64 컨벤션)

    // (5) 스택의 맨 위에 fake return address 추가
    stack_ptr--;
    *stack_ptr = 0;

    // (6) 스택 추가가 끝났으니, intr_frame의 %rsi %rdi 값도 변경
    if_->R.rsi = (uint64_t)stack_ptr + 8; // 시작점이 아니라, 스택의 맨 위에 있는 fake return address 다음부터 시작
    if_->R.rdi = argc;

    // (7) intr_frame의 유저 스택 포인터 rsp 값도 업데이트
    if_->rsp = stack_ptr;
}

/* 파일의 PHDR이 Valid하고 Load 가능한 세그먼트인지 확인하고 True/False를 반환하는 함수. */
static bool validate_segment(const struct Phdr *phdr, struct file *file) {

    /* p_offset and p_vaddr must have the same page offset. */
    if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
        return false;

    /* p_offset must point within FILE. */
    if (phdr->p_offset > (uint64_t)file_length(file))
        return false;

    /* p_memsz must be at least as big as p_filesz. */
    if (phdr->p_memsz < phdr->p_filesz)
        return false;

    /* The segment must not be empty. */
    if (phdr->p_memsz == 0)
        return false;

    /* The virtual memory region must both start and end within the
       user address space range. */
    if (!is_user_vaddr((void *)phdr->p_vaddr))
        return false;
    if (!is_user_vaddr((void *)(phdr->p_vaddr + phdr->p_memsz)))
        return false;

    /* The region cannot "wrap around" across the kernel virtual
       address space. */
    if (phdr->p_vaddr + phdr->p_memsz < phdr->p_vaddr)
        return false;

    /* Disallow mapping page 0.
       Not only is it a bad idea to map page 0, but if we allowed
       it then user code that passed a null pointer to system calls
       could quite likely panic the kernel by way of null pointer
       assertions in memcpy(), etc. */
    if (phdr->p_vaddr < PGSIZE)
        return false;

    /* It's okay. */
    return true;
}

#ifndef VM // 아래 load_segment(), install_page(), setup_stack()은 Project 2에서만 사용

/* load_segment() 보조 함수 Prototype */
static bool install_page(void *upage, void *kpage, bool writable);

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    file_seek(file, ofs);
    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* Get a page of memory. */
        uint8_t *kpage = palloc_get_page(PAL_USER);
        if (kpage == NULL)
            return false;

        /* Load this page. */
        if (file_read(file, kpage, page_read_bytes) != (int)page_read_bytes) {
            palloc_free_page(kpage);
            return false;
        }
        memset(kpage + page_read_bytes, 0, page_zero_bytes);

        /* Add the page to the process's address space. */
        if (!install_page(upage, kpage, writable)) {
            printf("fail\n");
            palloc_free_page(kpage);
            return false;
        }

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a minimal stack by mapping a zeroed page at the USER_STACK */
static bool setup_stack(struct intr_frame *if_) {
    uint8_t *kpage;
    bool success = false;

    kpage = palloc_get_page(PAL_USER | PAL_ZERO);
    if (kpage != NULL) {
        success = install_page(((uint8_t *)USER_STACK) - PGSIZE, kpage, true);
        if (success)
            if_->rsp = USER_STACK;
        else
            palloc_free_page(kpage);
    }
    return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
 * virtual address KPAGE to the page table.
 * If WRITABLE is true, the user process may modify the page;
 * otherwise, it is read-only.
 * UPAGE must not already be mapped.
 * KPAGE should probably be a page obtained from the user pool
 * with palloc_get_page().
 * Returns true on success, false if UPAGE is already mapped or
 * if memory allocation fails. */
static bool install_page(void *upage, void *kpage, bool writable) {
    struct thread *t = thread_current();

    /* Verify that there's not already a page at that virtual
     * address, then map our page there. */
    return (pml4_get_page(t->pml4, upage) == NULL && pml4_set_page(t->pml4, upage, kpage, writable));
}
#else

////////////////////////////////////////////////////////////////////////////////
///////////////////////////////// Project 3 ++ /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* From here, codes will be used after project 3.
 * If you want to implement the function for only project 2, implement it on the
 * upper block. */

static bool lazy_load_segment(struct page *page, void *aux) {
    /* TODO: Load the segment from the file */
    /* TODO: This called when the first page fault occurs on address VA. */
    /* TODO: VA is available when calling this function. */
}

/* Loads a segment starting at offset OFS in FILE at address
 * UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
 * memory are initialized, as follows:
 *
 * - READ_BYTES bytes at UPAGE must be read from FILE
 * starting at offset OFS.
 *
 * - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.
 *
 * The pages initialized by this function must be writable by the
 * user process if WRITABLE is true, read-only otherwise.
 *
 * Return true if successful, false if a memory allocation error
 * or disk read error occurs. */
static bool load_segment(struct file *file, off_t ofs, uint8_t *upage, uint32_t read_bytes, uint32_t zero_bytes, bool writable) {
    ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
    ASSERT(pg_ofs(upage) == 0);
    ASSERT(ofs % PGSIZE == 0);

    while (read_bytes > 0 || zero_bytes > 0) {
        /* Do calculate how to fill this page.
         * We will read PAGE_READ_BYTES bytes from FILE
         * and zero the final PAGE_ZERO_BYTES bytes. */
        size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
        size_t page_zero_bytes = PGSIZE - page_read_bytes;

        /* TODO: Set up aux to pass information to the lazy_load_segment. */
        void *aux = NULL;
        if (!vm_alloc_page_with_initializer(VM_ANON, upage, writable, lazy_load_segment, aux))
            return false;

        /* Advance. */
        read_bytes -= page_read_bytes;
        zero_bytes -= page_zero_bytes;
        upage += PGSIZE;
    }
    return true;
}

/* Create a PAGE of stack at the USER_STACK. Return true on success. */
static bool setup_stack(struct intr_frame *if_) {
    bool success = false;
    void *stack_bottom = (void *)(((uint8_t *)USER_STACK) - PGSIZE);

    /* TODO: Map the stack on stack_bottom and claim the page immediately.
     * TODO: If success, set the rsp accordingly.
     * TODO: You should mark the page is stack. */
    /* TODO: Your code goes here */

    return success;
}
#endif /* VM */
