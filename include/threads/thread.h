#ifndef THREADS_THREAD_H
#define THREADS_THREAD_H

#include <debug.h>
#include <list.h>
#include <stdint.h>

#include "threads/interrupt.h"
#include "threads/synch.h"    // fd_lock을 스레드마다 구현하기 위함
#include "userprog/process.h" // child_exit_status 참고용

#ifdef VM
#include "vm/vm.h"
#endif

/* States in a thread's life cycle. */
enum thread_status {
    THREAD_RUNNING, /* Running thread. */
    THREAD_READY,   /* Not running but ready to run. */
    THREAD_BLOCKED, /* Waiting for an event to trigger. */
    THREAD_DYING    /* About to be destroyed. */
};

/* Thread identifier type.
   You can redefine this to whatever type you like. */
typedef int tid_t;
#define TID_ERROR ((tid_t)-1) /* Error value for tid_t. */

/* Process Identifier Type */
typedef int pid_t;
#define PID_ERROR ((pid_t)-1) /* Error value for tid_t. */

/* Thread priorities. */
#define PRI_MIN 0      /* Lowest priority. */
#define PRI_DEFAULT 31 /* Default priority. */
#define PRI_MAX 63     /* Highest priority. */

/* (Updated) A kernel thread or user process.
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
    tid_t tid;                 /* Thread identifier 번호 */
    enum thread_status status; /* Thread state (RUNNING 등) */
    char name[16];             /* Name (디버깅 목적으로 활용) */
    int priority;              /* Priority (함수들이 참고하는 실제 우선순위) */

    /* Alarm Clock 구현을 위해서 추가 */
    int64_t wake_tick; // 스레드가 Sleep된다면, 깨어나야 할 System Tick 수치를 여기에 저장

    /* Priority Donation을 위한 멤버들 */
    int priority_original;          // 최초 부여된 우선순위를 저장하는 부분 (Donation이 다 끝났을 때 참고 목적)
    struct lock *waiting_for_lock;  // 스레드가 특정 락을 기다리고 있을 경우 여기에 저장
    struct list donations;          // 다른 스레드가 우선순위를 기부했을 경우 여기에 저장
    struct list_elem donation_elem; // 우선순위를 기부할 경우 이 포인터를 해당 스레드의 donations 리스트에 저장

    struct list_elem elem; /* 원래 포함되어 있는, 가장 기본적인 thread elem */

    // #ifdef USERPROG

    /* 기본적으로 포함되어있는 멤버 */
    uint64_t *pml4; /* Page map level 4 */

    /* File Descriptor 관리를 위한 멤버 */
    struct lock fd_lock;    // Allocate_fd()에서 사용되는 락, per thread
    struct file **fd_table; // File Descriptor Table ; init_thread에서 한번 초기화

    /* process_wait() 및 exit()을 위해서 추가된 멤버 */

    struct semaphore fork_sema;       // Parent의 process_fork와 Child의 _do_fork 사이에서 활동 (포크 완료 여부)
    struct semaphore wait_sema;       // Parent의 process_wait과 Child의 process_exit 사이에서 활동 (자식 사망 여부)
    struct semaphore free_sema;       // Parent의 process_wait과 Child의 process_exit 사이에서 활동 (진짜 죽어도 되는지 여부)
    struct intr_frame tf_backup_fork; // fork 과정에서 스냅샷 임시 저장용 멤버

    struct thread *parent_is;    // 부모를 가리키는 포인터
    struct list children_list;   // 특정 스레드가 발생시킨 Child의 명단
    struct list_elem child_elem; // children 리스트 삽입 목적

    int exit_status;     // 프로세스 종료시 exit status 코드 저장
    bool already_waited; // 해당 child에 대한 process_wait()이 이미 호출되었다면 true (False로 init 필요)

    /* Child_exit_status 관리를 위한 멤버 */
    struct lock exited_child_lock;    // Allocate_fd()에서 사용되는 락, per thread
    struct list exited_children_list; // 특정 스레드가 발생시킨 Child의 명단

    // #endif
#ifdef VM
    /* Table for whole virtual memory owned by thread. */
    struct supplemental_page_table spt;
#endif

    /* Owned by thread.c. */
    struct intr_frame tf; /* Information for switching */
    unsigned magic;       /* Detects stack overflow. */
};

/* If false (default), use round-robin scheduler.
   If true, use multi-level feedback queue scheduler.
   Controlled by kernel command-line option "-o mlfqs". */
extern bool thread_mlfqs;

void thread_init(void);
void thread_start(void);

void thread_tick(void);
void thread_print_stats(void);

typedef void thread_func(void *aux);
tid_t thread_create(const char *name, int priority, thread_func *, void *);

void thread_block(void);
void thread_unblock(struct thread *);

struct thread *thread_current(void);
tid_t thread_tid(void);
const char *thread_name(void);

void thread_exit(void) NO_RETURN;
void thread_yield(void);

int thread_get_priority(void);
void thread_set_priority(int);

int thread_get_nice(void);
void thread_set_nice(int);
int thread_get_recent_cpu(void);
int thread_get_load_avg(void);

void do_iret(struct intr_frame *tf);

/* 최초 버전 대비 직접 추가한 함수 프로토타입들 */

void thread_sleep(int64_t wake_time_tick);
void thread_wake(int64_t current_tick);
bool comparison_for_sleeplist_insertion(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED);
bool comparison_for_readylist_insertion(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED);
bool comparison_for_priority_donation(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED);
void thread_check_yield(void);

#endif /* threads/thread.h */
