#include "userprog/syscall.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include <stdio.h>
#include <syscall-nr.h>

void syscall_entry(void);
void syscall_handler(struct intr_frame *);

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

/* The main system call interface */
void syscall_handler(struct intr_frame *f) {
    // TODO: Your implementation goes here.

    // Parameter로 주어지는 포인터들을 Validate 해야 함 (User area, valid address)
    // Argument들을 user stack에서 kernel로 복사해 와야 함

    // System Call Number를 통해서 실제 시스템콜을 호출해야 함
    // /pintos-kaist/include/lib/syscall-nr.h

    // return value는 %rax에 저장되어야 함

    // printf("system call!\n");
    // thread_exit();

    int syscall_num = f->R.rax;
    // printf("System call: %d\n", syscall_num);

    switch (syscall_num) {

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        // printf("write: %d\n", f->R.rax);
        break;

    default:
        printf("Unknown system call: %d\n", syscall_num);
        thread_exit();
    }

    //예외처리 더 해줘야함
    return -1;
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////// 구현 대상 System Call 함수들 ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

// void halt(void);

void exit(int status) {
    printf("%s: exit(%d)\n", thread_current()->name, status);
    //확실하지 않음
    // printf("%s\n", thread_current()->name);
    thread_exit();
}

// pid_t fork(const char *thread_name);
// int exec(const char *cmd_line);
// int wait(pid_t pid);
// bool create(const char *file, unsigned initial_size);
// bool remove(const char *file);
// int open(const char *file);
// int filesize(int fd);
// int read(int fd, void *buffer, unsigned size);

int write(int fd, const void *buffer, unsigned size) {
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