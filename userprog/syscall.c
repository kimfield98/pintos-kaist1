#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"

#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

/* 시스템콜 핸들러 함수 프로토타입 */
void syscall_entry(void);
void syscall_handler(struct intr_frame *);

/* 포인터 주소 확인 함수들 */
bool pointer_validity_check(void *addr);
bool buffer_validity_check(void *buffer, unsigned size);

/* 실제 시스템콜 함수 프로토타입 */
void halt(void);
void exit(int status);
pid_t fork(const char *thread_name);
int exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
// seek
// tell
// close

/* File Descriptor 관련 함수 Prototype & Global Variables */
int allocate_fd(struct file *file);
struct file *get_file_from_fd(int fd);
void release_fd(int fd);
void close_file(int fd);
void fd_table_destroy();

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// System Call Handlers //////////////////////////////
////////////////////////////////////////////////////////////////////////////////

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

void syscall_init(void) {
    write_msr(MSR_STAR, ((uint64_t)SEL_UCSEG - 0x10) << 48 | ((uint64_t)SEL_KCSEG) << 32);
    write_msr(MSR_LSTAR, (uint64_t)syscall_entry);

    /* The interrupt service rountine should not serve any interrupts
     * until the syscall_entry swaps the userland stack to the kernel
     * mode stack. Therefore, we masked the FLAG_FL. */
    write_msr(MSR_SYSCALL_MASK, FLAG_IF | FLAG_TF | FLAG_DF | FLAG_IOPL | FLAG_AC | FLAG_NT);
}

/* System Call Interface 역할을 하는 함수. */
void syscall_handler(struct intr_frame *f) {

    // 보통 유저-사이드에서 호출되는 시스템 전용 함수 내에서 rax를 셋업하고 커널로 INT N을 호출해서 넘어가게 되며,
    // 이 과정에서 %rdi, %rsi, %rdx, %r10, %r8, and %r9 레지스터 6개에 Argument도 탑재
    // System Call Number 참고 : /pintos-kaist/include/lib/syscall-nr.h

    // 유저가 레지스터로 전달하는 포인터들을 Validate 해야 함 (User area, valid address 여부)
    // 이 Argument들을 user stack에서 kernel로 복사해 와야 함 (커널에서 바로 유저 접근 지양)

    // 커널-사이드에서 실행된 결과물을 %rax에 넣어서 반환해야 함

    int syscall_num = f->R.rax;

    switch (syscall_num) {

    case SYS_HALT:
        break;

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    case SYS_FORK:
        break;

    case SYS_EXEC:
        break;

    case SYS_WAIT:
        break;

    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;

    case SYS_REMOVE:
        break;

    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_FILESIZE:
        break;

    case SYS_READ:
        break;

    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        // printf("write: %d\n", f->R.rax);
        break;

    case SYS_SEEK:
        break;

    case SYS_TELL:
        break;

    case SYS_CLOSE:
        break;

    default:
        printf("Unknown system call: %d\n", syscall_num);
        thread_exit();
    }

    /* Debug */
    // printf("System call: %d\n", syscall_num);
    // printf("system call!\n");
    // thread_exit();

    // 예외처리 더 해줘야함
    return;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////// Pointer Validity Checks /////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 유저 프로그램에게 전달받은 포인터를 검사하는 함수 */
bool pointer_validity_check(void *addr) {

    /* 제공된 주소가 NULL일 경우 */
    if (addr == NULL)
        return false;

    /* 제공된 주소가 User Space가 아닌 경우 (커널에 속하는 경우) */
    if (is_kernel_vaddr(addr))
        return false;

    /* 제공된 주소가 Unmapped일 경우 */
    if (pml4_get_page(thread_current()->pml4, addr) == NULL)
        return false; // pml4만 확인하는 함수 (실제로 핀토스에 나머지 pt들이 구현되어있는지 잘 모르겠음)

    /* 다 통과했으니 */
    return true;
}

/* 유저에게 전달받은 버퍼의 처음과 끝, 그리고 다시 중간을 검사하는 함수 (특히, 버퍼가 커서 복수의 페이지를 사용하는 경우) */
bool buffer_validity_check(void *buffer, unsigned size) {

    /* buffer의 최초 주소 (시작 주소)를 확인 */
    if (!pointer_validity_check(buffer))
        return false;

    /* buffer의 마지막 주소를 확인 */
    if (!pointer_validity_check(buffer + size - 1)) // GPT한데 코드를 확인받아보니, buffer+size가 딱 페이지의 끝일 경우 0으로 돌아가기 때문에 -1을 추천함
        return false;

    /* 각각의 페이지 크기 (PintOS는 4KB) */
    const size_t PAGE_SIZE = 4096;

    /* 버퍼의 시작과 끝주소를 정의 */
    uintptr_t start = (uintptr_t)buffer; // GPT 한테 확인 받아보니, 포인터를 담을 수 있는 자료형인 uintptr_t를 사용하는걸 권장
    uintptr_t end = start + size;        // 실제로 64x 시스템에서 int는 4B, 큰일날뻔

    /* 한 페이지가 Mapped 상태라면 문제 없으니, 그 다음 페이지를 확인하는 방식 */
    for (uintptr_t addr = start; addr < end; addr += PAGE_SIZE) {
        if (!pointer_validity_check((void *)addr)) {
            return false;
        }
    }

    /* 버퍼의 전체 영역이 Valid하니까 */
    return true;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////// 구현 대상 System Call 함수들 ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// void halt(void);

/* 현재 구동되던 유저 프로그램을 종료시키고, 커널로 Status값을 돌려주는 시스템콜.
   만일 프로세스의 Parent가 기다리고 있다면 status 값이 parent에게 전달됨.
   전통적으로 0은 Success, nonzero value는 실패를 의미함 (return). */
void exit(int status) {

    printf("%s: exit(%d)\n", thread_current()->name, status);

    thread_exit();
}

// pid_t fork(const char *thread_name);
// int exec(const char *cmd_line);
// int wait(pid_t pid);

/* 'file'이라는 이름을 가진 'initial_size' 바이트 크기의 파일을 새로 생성하는 시스템콜.
   성공하면 true, 실패하면 false를 반환하면 됨.
   생성에 성공한다고 해서 그 파일을 여는게 아님 (별도의 시스템콜로 진행됨) */
bool create(const char *file, unsigned initial_size) {

    if (!pointer_validity_check(file)) {
        exit(-1);
    }

    bool success = false;

    /* filesys.c의 filesys_create 함수 사용 ; 이 함수도 성공시 bool 반환 */
    success = filesys_create(file, initial_size);

    /* 따라서 그냥 그대로 돌려주면 됨 */
    return success;
}

// bool remove(const char *file);

/* 'file'이라는 이름을 가진 파일을 여는 시스템콜.
   file descriptor 값을 반환 (non negative integer). 실패시 -1.
   fd 값 0 (STDIN_FILENO) ; Standard Input 전용 번호
   fd 값 1 (STDIN_FILENO) ; Standard Output 전용 번호
   따라서 0과 1을 절대 반환할 수 없음.
   각 프로세스는 각자의 file descriptor set를 가지고 있음.
   이 file descriptor 값들은 child process에게도 승계됨.
   같은 파일이 여러번 열릴 경우 (단일/복수 프로세스 무관), 매번 새로운 fd 값이 생성됨.
   같은 파일이 각각 다른 fd 값을 갖는 만큼 각각 별도로 시스템콜을 통해서 닫아줘야 함.
   이 fd들은 파일 내 위치 포인터를 공유하지 않음. */
int open(const char *file) {

    if (!pointer_validity_check(file)) {
        exit(-1);
    }

    /* 파일을 열어보려고 시도하고, 실패시 -1 반환 (struct file 필수) */
    struct file *opened_file = filesys_open(file);
    if (!opened_file)
        return -1;

    /* File Descriptor 번호 부여 및 테이블에 삽입 */
    int fd = allocate_fd(opened_file);

    /* File Descriptor Table이 가득차면 그냥 파일 닫기 */
    if (fd == -1) {
        file_close(opened_file);
        return -1;
    }

    /* 여기까지 왔으면 성공했으니 fd값 반환 */
    return fd;
}

// int filesize(int fd);
// int read(int fd, void *buffer, unsigned size);

/* Open된 file fd에서 'size' 바이트만큼 'buffer'에 저장하는 시스템콜.
   성공시 Write한 바이트 크기를 반환하며, 요청보다 적을 수 있음.
   보통 End-of-file을 넘어서서 작성하게 될 경우 파일 크기가 커져야 하지만,
   PintOS에 제공되는 기본 파일시스템은 이 기능을 지원하지 않음.
   따라서 EoF까지 최대한 작성한 뒤에 성공한 글자 수를 반환하게 됨.
   fd == 1은 시스템 콘솔에 작성하는 Shortcut (테스트용).
   시스템 콘솔에 write하기 위한 코드는 buffer에 있는 모든 데이터를 putbuf()로 한번에 사용해야 함 (수백바이트 크기가 아니라면).
   한번에 putbuf()를 하지 않는다면 다양한 프로세스들의 아웃풋이 콘솔에 혼재되어 프린트되게 됨. */
int write(int fd, const void *buffer, unsigned size) {

    if (!buffer_validity_check(buffer, size)) {
        exit(-1);
    }

    if (fd == 1) {
        putbuf(buffer, size);
        return size;
    }

    return -1;
}

// void seek(int fd, unsigned position);
// unsigned tell(int fd);
// void close(int fd);

////////////////////////////////////////////////////////////////////////////////
////////////////////////// File Descriptor 전용 함수들 ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* init_thread()에서 palloc 으로 struct thread userprog의 struct file **fd_table을 초기화 했음 */

/* fd 번호를 새로 allocate 하는 함수 */
int allocate_fd(struct file *file) {

    struct thread *t = thread_current(); // user thread는 in the kernel이 된 상태 ; kernel thread가 아님

    lock_acquire(&t->fd_lock);
    /* init_thread()에서 palloc된 페이지를 탐색, 0으로 채워진 공간을 확보 */
    for (int i = 2; i < 128; i++) { // fd 0과 1번은 stdin stdout 전용이니 건너뛰어야 함 ; palloc 공간은 더 크지만 그냥 fd 개수는 128으로 제한
        if (t->fd_table[i] == 0) {  // palloc에서 0으로 공간을 채웠으니, 0이면 빈 공간
            t->fd_table[i] = file;  // 파일의 주소를 이 공간에 저장 (포인터/주소는 8바이트)
            lock_release(&t->fd_lock);
            return i; // i가 사실상 fd 값 역할
        }
    }
    lock_release(&t->fd_lock);
    return -1; // fd allocation에 실패할 경우
}

/* fd번호에서 실제 파일 포인터를 추출하는 함수 */
struct file *get_file_from_fd(int fd) {

    struct thread *t = thread_current();

    if (fd >= 2 && fd < 128) {
        return t->fd_table[fd];
    }
    return NULL; // Invalid fd
}

/* fd번호에 해당하는 공간을 0으로 다시 되돌리는 함수 */
void release_fd(int fd) {

    struct thread *t = thread_current();

    lock_acquire(&t->fd_lock);
    if (fd >= 2 && fd < 128) {
        t->fd_table[fd] = 0;
    }
    lock_release(&t->fd_lock);
}

/* fd 번호에 해당하는 파일을 닫고 fd를 풀어주는 함수 */
void close_file(int fd) {

    struct file *f = get_file_from_fd(fd);

    if (f) {
        file_close(f);
        release_fd(fd);
    }
}

/* fd 테이블을 비우고 메모리도 풀어주는 함수 (thread_exit 전에 호출) */
void fd_table_destroy() {

    struct thread *t = thread_current();

    for (int i = 2; i < 128; i++) {
        if (t->fd_table[i]) {
            file_close(t->fd_table[i]);
        }
    }
    palloc_free_page(t->fd_table);
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////// 공식 문서에서 제공되는 Helper 함수 ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 유저 프로그램에서 시스템콜이 발생할 경우, 커널은 유저 프로그램이 제공한 포인터들로 가상 메모리에 접근해야 함.
   유저 프로그램이 NULL, Unmapped, Kernel-section을 가리킬 수 있기 때문에 조심히 다뤄야 함.

   1번 방법 : 가장 간단한 방법 ; 매번 포인터를 받을 때마다 Validity Check 이후에 Dereference하는 방식 (thread/mmu.c 및 include/threads/vaddr.h 참고)
   2번 방법 : 빠르고 선호되는 방법 ; 포인터가 유저-커널 메모리 공간의 경계인 KERN_BASE 아래를 가리키는지 (유저 스페이스에 한정되는지)만 확인
   두번째 방법을 사용하려면 page_fault()를 수정해서 invalid pointer를 대응할 수 있도록 해야 함.

   중요: 1번 방식을 택할 경우 lock_acquire 및 palloc() 이전에 포인터를 확인하기 때문에 문제 없음 (avoid leak of resources).
   단, 2번 방식의 경우 invalid pointer 발생 시 lock_acquire/palloc()을 풀어주도록 신경 써야 함.
   특히 invalid poitner가 page_fault()를 발생시킬 경우 에러코드를 발생시킬 수 없게 됨.
   아래 2가지 함수는 2번 방식을 사용할 경우 필요할 보조 함수. */

/* Reads a byte at user virtual address UADDR.
 * UADDR must be below KERN_BASE.
 * Returns the byte value if successful, -1 if a segfault
 * occurred. */
static int64_t get_user(const uint8_t *uaddr) {
    int64_t result;
    __asm __volatile("movabsq $done_get, %0\n"
                     "movzbq %1, %0\n"
                     "done_get:\n"
                     : "=&a"(result)
                     : "m"(*uaddr));
    return result;
}

/* Writes BYTE to user address UDST.
 * UDST must be below KERN_BASE.
 * Returns true if successful, false if a segfault occurred. */
static bool put_user(uint8_t *udst, uint8_t byte) {
    int64_t error_code;
    __asm __volatile("movabsq $done_put, %0\n"
                     "movb %b2, %1\n"
                     "done_put:\n"
                     : "=&a"(error_code), "=m"(*udst)
                     : "q"(byte));
    return error_code != -1;
}