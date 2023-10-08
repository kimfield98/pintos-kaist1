#include "threads/thread.h"
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/intr-stubs.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/vaddr.h"
#include <debug.h>
#include <random.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>
#ifdef USERPROG
#include "userprog/process.h"
#endif

/* 기본적인 Declaration & Macro */

#define THREAD_MAGIC 0xcd6abf4b // Struct Thread를 위한 Magic Number (스택 오버플로우 감지용)
#define THREAD_BASIC 0xd42df210 // Basic Thread를 위한 랜덤 값 (수정 금지)
#define TIME_SLICE 4            // 각 스레드마다 부여되는 Timer Tick의 크기

static struct thread *idle_thread;    // 스케쥴링할 스레드가 없을 때 호출되는 특수한 스레드 - Idle thread
static struct thread *initial_thread; // Init.c의 main()에서 운영되는 최초의 스레드 - Initial thread
static struct lock tid_lock;          // Allocate_tid()에서 사용되는 락

static struct list ready_list;      // THREAD_READY로 대기중인 프로세스들을 위한 리스트 (Run 준비 완료 상태)
static struct list sleep_list;      // Sleep 상태의 스레드들을 저장해두는 리스트 (우선순위가 높으면 앞에 배치)
static struct list destruction_req; // 삭제할 스레드들을 임시 저장하는 리스트 (do_schedule에서 처리)

/* 시스템 통계 및 타이머에서 활용하는 Ticks */

static long long idle_ticks;   // Idle 상태로 보낸 Timer Tick의 수
static long long kernel_ticks; // Kernel 스레드가 사용한 Timer Tick의 수
static long long user_ticks;   // User Program에서 사용된 Timer Tick의 수
static unsigned thread_ticks;  // 마지막 Yield 이후로 지난 Timer Tick의 수

/* MLFQS 사용 여부를 반환 ; 기본값은 False이며, Round-robin 스케쥴러를 활용한다는 의미 ("-o mlfqs"로 통제) */

bool thread_mlfqs;

/* Static 함수 프로토타입 (Thread.c로 한정되어 사용되는 함수들 ; 기타 나머지는 Thread.h 참고) */

static void kernel_thread(thread_func *, void *aux);
static void idle(void *aux UNUSED);
static struct thread *next_thread_to_run(void);
static void init_thread(struct thread *, const char *name, int priority);
static void do_schedule(int status);
static void schedule(void);
static tid_t allocate_tid(void);

#define is_thread(t) ((t) != NULL && (t)->magic == THREAD_MAGIC) // Parameter가 Valid 스레드인지 여부 반환 (True/False)
#define running_thread() ((struct thread *)(pg_round_down(rrsp()))) // 현재 스레드를 가리키는 포인터 반환 (스택 포인터 rsp를 페이지의 시작으로 round ; struct thread는 항상 맨앞에 위치)

/* Thread_start()에서 사용되는 Global Descriptor Table (GDT) ; Thread_init에서 재대로 만들어지기 때문에 사용되는 임시 GDT 개념 */

static uint64_t gdt[3] = {0, 0x00af9a000000ffff, 0x00cf92000000ffff};

////////////////////////////////////////////////////////////////////////////////
/////////////////////////////// Thread.c 시작 ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 스레드 시스템을 초기화하는 함수로, 현재 실행중인 코드를 하나의 스레드로 변환.
   보통 이런식으로 구현되지 않으나, PintOS의 loader.S가 stack의 끝부분을 페이지 끝자락에 위치하도록 설계되어 아래처럼 활용 가능.
   thread_init() 이후에 page allocator를 재대로 초기화 해주어야 thread_create()를 사용할 수 있음.
   thread_init()이 재대로 수행되기 전까지 thread_current()를 부르면 안됨. */
void thread_init(void) {

    /* 시스템 구동 단계에서는 Interrupt가 무조건 꺼져 있음 */
    ASSERT(intr_get_level() == INTR_OFF);

    /* 위에 선언했던 Temporary GDT를 커널에 로딩하는 작업 (추후 gdt_init()에서 재대로 GDT 설정) */
    struct desc_ptr gdt_ds = {.size = sizeof(gdt) - 1, .address = (uint64_t)gdt};
    lgdt(&gdt_ds);

    /* 글로벌 Thread Context를 초기화 */
    lock_init(&tid_lock);
    list_init(&ready_list);
    list_init(&sleep_list);
    list_init(&destruction_req);

    /* 구동되기 시작한 Initial Thread의 Struct Thread 값을 설정 */
    initial_thread = running_thread();
    init_thread(initial_thread, "main", PRI_DEFAULT);
    initial_thread->status = THREAD_RUNNING;
    initial_thread->tid = allocate_tid();
}

/* Preemptive 스케쥴링 시스템을 구동시키는 함수. */
void thread_start(void) {

    /* Idle Thread를 생성 */
    struct semaphore idle_started;
    sema_init(&idle_started, 0);
    thread_create("idle", PRI_MIN, idle, &idle_started);

    /* Preemptive 스레드 스케쥴링 시작. */
    intr_enable();

    /* Idle Thread를 접근하기 위해서 대기 상태로 진입 */
    sema_down(&idle_started);
}

/* Timer Interrupt Handler가 매 틱마다 호출하는 함수 (External Interrupt Context 전용) */
void thread_tick(void) {

    struct thread *t = thread_current();

    /* 시스템 통계값 갱신 */
    if (t == idle_thread)
        idle_ticks++;
#ifdef USERPROG
    else if (t->pml4 != NULL)
        user_ticks++;
#endif
    else
        kernel_ticks++;

    /* Preemption이 자동으로 TIME_SLICE마다 발생하도록 함 */
    if (++thread_ticks >= TIME_SLICE)
        intr_yield_on_return();
}

/* 스레드 관련 통계치들을 출력하는 함수 */
void thread_print_stats(void) { printf("Thread: %lld idle ticks, %lld kernel ticks, %lld user ticks\n", idle_ticks, kernel_ticks, user_ticks); }

/* 새로은 커널 스레드를 생성하는 함수.
   Name 및 Priority를 부여하고, Function/Aux를 실행하는 스레드.
   생성 이후 ready_list에 삽입되며, 성공하면 TID를, 실패하면 에러를 반환. */
tid_t thread_create(const char *name, int priority, thread_func *function, void *aux) {

    struct thread *t;
    tid_t tid;

    ASSERT(function != NULL);

    /* 스레드에 페이지 부여 */
    t = palloc_get_page(PAL_ZERO);
    if (t == NULL) {
        palloc_free_page(t);
        return TID_ERROR;
    }

    /* 스레드 초기화 작업 */
    init_thread(t, name, priority);
    tid = t->tid = allocate_tid();

    // #ifdef USERPROG

    /* fd_table의 메모리 부여 및 락 초기화가 여기서 일어나야 문제가 없음 */
    t->fd_table = (struct file **)palloc_get_page(0); // User-side에 0으로 초기화된 페이지를 새로 Allocate
    lock_init(&t->fd_lock);
    list_push_back(&thread_current()->children_list, &t->child_elem); // 부모 스레드의 children_list에 자식 스레드를 추가
    t->parent_is = thread_current();
    // #endif

    /* 커널 스레드가 ready_list에 있다면 호출, Function/Aux 값을 부여 */
    t->tf.rip = (uintptr_t)kernel_thread;
    t->tf.R.rdi = (uint64_t)function;
    t->tf.R.rsi = (uint64_t)aux;
    t->tf.ds = SEL_KDSEG;
    t->tf.es = SEL_KDSEG;
    t->tf.ss = SEL_KDSEG;
    t->tf.cs = SEL_KCSEG;
    t->tf.eflags = FLAG_IF;

    /* 기본적인 스레드 골격을 생성했으니 ready_list에 삽입 */
    thread_unblock(t);

    /* 새로 생성된 스레드의 우선순위가 Run 중인 스레드보다 높다면 스케쥴러 호출 */
    if (t->priority > thread_current()->priority) {
        thread_yield();
    }

    return tid;
}

/* 현재 Run 상태인 스레드를 Sleep 상태로 바꾸는 함수.
   thread_unblock()으로 풀어주기 전까지 ready_list에 복귀 불가.
   Interrupt를 끈 상태에서 호출해야하며, interrupt가 호출하는 형태는 복잡도가 급격히 증가하기 때문에 금지. */
void thread_block(void) {

    ASSERT(!intr_context());
    ASSERT(intr_get_level() == INTR_OFF);
    thread_current()->status = THREAD_BLOCKED;
    schedule();
}

/* thread_block()으로 재워둔 스레드를 다시 ready_list로 복귀시키는 함수.
   스레드가 block상태가 아니라면 에러를 반환 (따라서 Running 스레드를 ready_list로 넣을때는 사용 금지).

   중요 : 이 함수는 기존에 Run 상태인 스레드를 Preempt 하지 않아야 함. */
void thread_unblock(struct thread *t) {

    /* 스레드인지 검증하고, Interrupt를 끈 뒤에 스레드의 상태를 검증 (다른 스레드가 값을 그 사이에 바꾸지 못하도록) */
    ASSERT(is_thread(t));
    enum intr_level old_level = intr_disable();
    ASSERT(t->status == THREAD_BLOCKED);

    /* 우선순위가 높은 스레드가 앞으로 가도록 순서대로 스레드의 Elem을 ready_list에 삽입 */
    list_insert_ordered(&ready_list, &t->elem, comparison_for_readylist_insertion, NULL);
    t->status = THREAD_READY;

    /* Interrupt 활성화 */
    intr_set_level(old_level);
}

/* Timer.c의 timer_sleep() 함수가 호출하는, 스레드를 재우는 함수 */
void thread_sleep(int64_t wake_time_tick) {
    struct thread *curr = thread_current();
    enum intr_level old_level = intr_disable();

    /* 만일 현재 스레드가 idle thread라면 재우면 안됨 */
    if (curr != idle_thread) {
        curr->wake_tick = wake_time_tick; // Struct Thread의 wake_tick 값을 설정 (잠에 깨야하는 Tick)
        curr->status = THREAD_BLOCKED;
        list_insert_ordered(&sleep_list, &curr->elem, comparison_for_sleeplist_insertion, NULL);
    }

    /* schedule() 후속 작업을 위해서는 Interrupt가 꺼져있어야 함 ; 관련 작업 완료 후 추후 이 스레드로 돌아온다면 intr_set_level로 복귀해서 출발 */
    schedule();
    intr_set_level(old_level);
}

/* ready_list에 스레드를 추가하기 위해서 우선순위를 비교하는, list_insert_ordered() 전용 함수 */
bool comparison_for_readylist_insertion(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED) {

    struct thread *t_new = list_entry(new, struct thread, elem);
    struct thread *t_existing = list_entry(existing, struct thread, elem);

    return t_new->priority > t_existing->priority;
}

/* sleep_list에 스레드를 추가하기 위해서 깨야하는 시간 (목표 tick)을 비교하는, list_insert_ordered 전용 함수 */
bool comparison_for_sleeplist_insertion(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED) {

    struct thread *t_new = list_entry(new, struct thread, elem);
    struct thread *t_existing = list_entry(existing, struct thread, elem);

    return t_new->wake_tick < t_existing->wake_tick;
}

/* Timer.c의 timer_interrupt(), 즉 Interrupt Handler가 호출하는 함수 (스레드를 깨우는 역할) */
void thread_wake(int64_t current_tick) {

    /* sleep_list가 비어있는지 먼저 확인 후 하나씩 검토, 한번에 여러개를 깨워야 할 수도 있음 */
    while (!list_empty(&sleep_list)) {
        struct list_elem *target_elem_in_list = list_front(&sleep_list);
        struct thread *target_thread_from_elem = list_entry(target_elem_in_list, struct thread, elem);

        /* sleep_list는 깨워야하는 tick이 작을수록 앞에 있음 ; 따라서 조회하는 스레드의 wake tick이 시스템 값보다 크다면 멈춰도 됨 */
        if (target_thread_from_elem->wake_tick > current_tick)
            break;

        list_pop_front(&sleep_list);
        thread_unblock(target_thread_from_elem);
    }
}

/* 현재 Run 중인 스레드를 가리키는 포인터를 반환하는 함수 (running_thread의 Wrapper함수). */
struct thread *thread_current(void) {
    struct thread *t = running_thread();

    /* running_thread()의 wrapper로, 스택 오버플로우 여부 등을 확인 */
    ASSERT(is_thread(t));
    ASSERT(t->status == THREAD_RUNNING);

    return t;
}

/* 현재 Run 중인 스레드의 이름을 반환하는 함수 */
const char *thread_name(void) { return thread_current()->name; }

/* 현재 Run 중인 스레드의 TID 값을 반환 */
tid_t thread_tid(void) { return thread_current()->tid; }

/* 현재 Run 중인 스레드를 스케쥴러에서 제거하고 삭제 대상으로 지정하는 함수. */
void thread_exit(void) {
    ASSERT(!intr_context());

#ifdef USERPROG

    process_exit();

#endif

    /* THREAD_DYING으로 지정하고 스케쥴러를 호출, do_schedule에서 삭제 대상들을 일괄 삭제 */
    intr_disable();
    do_schedule(THREAD_DYING);
    NOT_REACHED();
}

/* CPU 사용 권한을 Yield 시키는 함수.
   현재 운영 중이던 스레드는 Sleep 상태로 진입하지 않으며, 스케쥴러에 의해서 즉시 다시 CPU 권한을 받을 수도 있음. */
void thread_yield(void) {

    ASSERT(!intr_context());

    enum intr_level old_level = intr_disable();
    struct thread *curr = thread_current();

    /* Idle thread에서는 구동되면 안되니 ready_list 삽입 코드를 보호 */
    if (curr != idle_thread)
        list_insert_ordered(&ready_list, &curr->elem, comparison_for_readylist_insertion, NULL); // (Edited)

    do_schedule(THREAD_READY);
    intr_set_level(old_level);
}

/* thread_yield를 하기 전에 한번 주요 조건들을 확인하는 Wrapper 함수. */
void thread_check_yield(void) {

    /* ready_list가 비어있지 않고, ready_list에서 제일 우선순위가 높은 스레드의 우선순위가 현재 run 중인 스레드의 우선순위보다 높을 경우 */
    /* project 2 하면서 추가 : interrupt handler가 디스크 loading 시점에서 sema_up을 하기도 함 ; 따라서 !intr_context() 필수 */
    if (!list_empty(&ready_list) && list_entry(list_front(&ready_list), struct thread, elem)->priority > thread_current()->priority && !intr_context()) {
        thread_yield();
    }
}

/* 현재 Run 중인 스레드의 우선순위를 변경하는 함수 */
void thread_set_priority(int new_priority) {

    /* 스레드의 우선순위 값들을 변경 (부스트 목적이 아닌 전체 변경) */
    thread_current()->priority_original = new_priority;
    thread_current()->priority = new_priority;

    /* Donation 수행 */
    if (!list_empty(&thread_current()->donations)) {                                     // 현재 스레드의 Donation 리스트에 내용물이 있다면,
        list_sort(&thread_current()->donations, comparison_for_priority_donation, NULL); // 해당 리스트를 우선순위에 따라 정렬하고,

        // 정렬된 리스트에서 제일 우선순위가 높은 스레드를 정의한 뒤에,
        struct thread *t = list_entry(list_front(&thread_current()->donations), struct thread, donation_elem);

        if (t->priority > thread_current()->priority) { // 만일 해당 스레드의 우선순위가 현재 스레드보다 더 높다면,
            thread_current()->priority = t->priority;   // 현재 스레드의 우선순위를 업데이트.
        }
    }

    /* thread_yield 전용 Wrapper 함수로, 조건부 thread_yield 수행 (ready_list에 현재 스레드보다 우선순위가 높은 스레드가 있을 경우) */
    thread_check_yield();
}

/* thread_set_priority 전용 헬퍼 함수 */
bool comparison_for_priority_donation(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED) {

    struct thread *t_new = list_entry(new, struct thread, donation_elem);
    struct thread *t_existing = list_entry(existing, struct thread, donation_elem);

    return t_new->priority > t_existing->priority;
}

/* 현재 Run 중인 스레드의 우선순위 값을 호출하는 함수 */
int thread_get_priority(void) { return thread_current()->priority; }

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// Thread.c 잠시 중단 /////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* 아래는 아직 활용하지 않는 함수들의 모음 (MLFQS 또는 기타 다른 작업에서 필요) */

/* Sets the current thread's nice value to NICE. */
void thread_set_nice(int nice UNUSED) { /* TODO: Your implementation goes here */
}

/* Returns the current thread's nice value. */
int thread_get_nice(void) {
    /* TODO: Your implementation goes here */
    return 0;
}

/* Returns 100 times the system load average. */
int thread_get_load_avg(void) {
    /* TODO: Your implementation goes here */
    return 0;
}

/* Returns 100 times the current thread's recent_cpu value. */
int thread_get_recent_cpu(void) {
    /* TODO: Your implementation goes here */
    return 0;
}

////////////////////////////////////////////////////////////////////////////////
//////////////////////////// Thread.c 다시 시작 ///////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* Idle 스레드를 위한 전용 함수 (스레드가 실행하고 있는 코드).
   이 스레드는 특수 스레드로, 스케쥴러가 CPU를 할당할 스레드가 없을 때 활용 (ready_list가 비어있을 경우).
   최초 스레드 시스템 초기화 과정에서 ready_list에 넣지만, 그 이후 다시는 ready_list에 넣지 않음.
   더 이상 구동할 스레드가 없을 때 next_thread_to_run()에서 explicit 하게 지정하는 형태. */
static void idle(void *idle_started_ UNUSED) {

    struct semaphore *idle_started = idle_started_;

    idle_thread = thread_current();
    sema_up(idle_started);

    /* 종료되지 않도록 무제한 반복문 형태로 구성 */
    for (;;) {
        intr_disable(); // Interrupt를 끄고,
        thread_block(); // Unblock 상태로 무한정 대기

        /* STI를 통해서 딱 한 instruction에 해당하는 기간만큼 Interrupt를 켜고,
           HLT를 통해서 CPU를 low-power mode로 잠깐 전환 (한 instruction 내에서 atomic하게).
           정리하자면 : STI가 Interrupt를 켰지만 HLT로 CPU가 바로 쉬러 들어가며, Interrupt 대기 상태로 진입.
           [IA32-v2a] "HTL", [IA32-v2b] "STI", [IA32-v3a] 7.11.1 "HTL Instruction" 참고 요망. */
        asm volatile("sti; hlt" : : : "memory");
    }
}

/* 커널 스레드를 위한 전용 함수 */
static void kernel_thread(thread_func *function, void *aux) {

    ASSERT(function != NULL);

    intr_enable(); // Scheduler는 Interrupt를 끈 상태이니, 켜줘야 함.
    function(aux);
    thread_exit(); // Function의 실행이 끝나고 나면 스레드를 exit (삭제)
}

/* 스레드 생성 시 Struct Thread의 내용들을 초기화해주는 함수 */
static void init_thread(struct thread *t, const char *name, int priority) {

    ASSERT(t != NULL);
    ASSERT(PRI_MIN <= priority && priority <= PRI_MAX);
    ASSERT(name != NULL);

    memset(t, 0, sizeof *t);
    t->status = THREAD_BLOCKED;
    strlcpy(t->name, name, sizeof t->name);
    t->tf.rsp = (uint64_t)t + PGSIZE - sizeof(void *);
    t->priority = priority;
    t->priority_original = priority; // 최초 부여된 우선순위를 저장하는 역할 (건드리지 않음)
    t->waiting_for_lock = NULL;      // 스레드가 특정 락을 기다리며 Block 상태로 들어갔을 때 설정
    list_init(&t->donations);        // 우선순위를 기부받는다면 저장하는 리스트
    t->magic = THREAD_MAGIC;

    /* Fork, Exec, Wait 관련 멤버들 활성화 */
    list_init(&t->children_list);
    sema_init(&t->fork_sema, 0); // Fork 관점 ; child의 _sema 사용 ; 부모는 해당 child를 down 하면서 대기 (process_fork), 자식은 _do_fork 끝자락에 up 해서 fork 완성 알림
    sema_init(&t->wait_sema, 0); // Fork 관점 ; child의 _sema 사용 ; 부모는 해당 child를 down 하면서 대기 (process_wait), 자식은 process_exit에서 up해서 본인이 끝남을 알림
    sema_init(&t->free_sema, 0); // Fork 관점 ; child의 _sema 사용 ; 자식은 exit wait_sema up 이후에 free_sema를 down 하며 대기, 부모는 wait_sema down 통과시 child의 exit 값 호출
    t->parent_is = NULL;         // 부모 없음
    t->exit_status = -999;       // 오지 않을 숫자로 초기화
}

/* CPU를 할당받을 다음 스레드를 고르는 함수 (idle thread가 여기서 적용) */
static struct thread *next_thread_to_run(void) {

    if (list_empty(&ready_list))
        return idle_thread;
    else
        return list_entry(list_pop_front(&ready_list), struct thread, elem);
}

/* Interrupted Thread 복구 함수 (저장했던 값들을 Register 등에 복구 ; ends in iretq) */
void do_iret(struct intr_frame *tf) {

    __asm __volatile("movq %0, %%rsp\n"
                     "movq 0(%%rsp),%%r15\n"
                     "movq 8(%%rsp),%%r14\n"
                     "movq 16(%%rsp),%%r13\n"
                     "movq 24(%%rsp),%%r12\n"
                     "movq 32(%%rsp),%%r11\n"
                     "movq 40(%%rsp),%%r10\n"
                     "movq 48(%%rsp),%%r9\n"
                     "movq 56(%%rsp),%%r8\n"
                     "movq 64(%%rsp),%%rsi\n"
                     "movq 72(%%rsp),%%rdi\n"
                     "movq 80(%%rsp),%%rbp\n"
                     "movq 88(%%rsp),%%rdx\n"
                     "movq 96(%%rsp),%%rcx\n"
                     "movq 104(%%rsp),%%rbx\n"
                     "movq 112(%%rsp),%%rax\n"
                     "addq $120,%%rsp\n"
                     "movw 8(%%rsp),%%ds\n"
                     "movw (%%rsp),%%es\n"
                     "addq $32, %%rsp\n"
                     "iretq"
                     :
                     : "g"((uint64_t)tf)
                     : "memory");
}

/* Context Switching을 수행하는 메인 함수 (do_iret()을 활용하는 함수).
   이 함수가 호출되는 시점은 PREV 스레드에서 스위칭이 완료 된 시점이며, 새로운 스레드가 이미 Running 상태.
   Interrupt는 여전히 꺼져 있어야 함. */
static void thread_launch(struct thread *th) {

    uint64_t tf_cur = (uint64_t)&running_thread()->tf;
    uint64_t tf = (uint64_t)&th->tf;
    ASSERT(intr_get_level() == INTR_OFF);

    /* intr_frame으로 모든 execution context를 저장하고, do_iret()으로 다음 스레드로 전환 */
    __asm __volatile(
        /* Register 값 임시저장 */
        "push %%rax\n"
        "push %%rbx\n"
        "push %%rcx\n"
        /* Input을 한번 가져와야 함 */
        "movq %0, %%rax\n"
        "movq %1, %%rcx\n"
        "movq %%r15, 0(%%rax)\n"
        "movq %%r14, 8(%%rax)\n"
        "movq %%r13, 16(%%rax)\n"
        "movq %%r12, 24(%%rax)\n"
        "movq %%r11, 32(%%rax)\n"
        "movq %%r10, 40(%%rax)\n"
        "movq %%r9, 48(%%rax)\n"
        "movq %%r8, 56(%%rax)\n"
        "movq %%rsi, 64(%%rax)\n"
        "movq %%rdi, 72(%%rax)\n"
        "movq %%rbp, 80(%%rax)\n"
        "movq %%rdx, 88(%%rax)\n"
        "pop %%rbx\n" // 저장된 rcx (Count Register)
        "movq %%rbx, 96(%%rax)\n"
        "pop %%rbx\n" // 저장된 rbx (Base Register)
        "movq %%rbx, 104(%%rax)\n"
        "pop %%rbx\n" // 저장된 rax (Accumulator Register)
        "movq %%rbx, 112(%%rax)\n"
        "addq $120, %%rax\n"
        "movw %%es, (%%rax)\n"
        "movw %%ds, 8(%%rax)\n"
        "addq $32, %%rax\n"
        "call __next\n" // 현재 rip값을 read (Instruction Pointer)
        "__next:\n"
        "pop %%rbx\n"
        "addq $(out_iret -  __next), %%rbx\n"
        "movq %%rbx, 0(%%rax)\n" // rip (Instruction Pointer)
        "movw %%cs, 8(%%rax)\n"  // cs (Code Segment)
        "pushfq\n"
        "popq %%rbx\n"
        "mov %%rbx, 16(%%rax)\n" // eflags (Flags Register)
        "mov %%rsp, 24(%%rax)\n" // rsp (Stack Pointer)
        "movw %%ss, 32(%%rax)\n"
        "mov %%rcx, %%rdi\n"
        "call do_iret\n"
        "out_iret:\n"
        :
        : "g"(tf_cur), "g"(tf)
        : "memory");
}

/* 새로운 스레드를 스케쥴링하는 함수 (Interrupt가 꺼진 상태여야 함).
   현 스레드의 status를 수정하고 다른 스레드를 골라서 스위칭까지 수행. */
static void do_schedule(int status) {

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(thread_current()->status == THREAD_RUNNING);

    /* Exit한 함수들을 실제로 삭제 */
    while (!list_empty(&destruction_req)) {
        struct thread *victim = list_entry(list_pop_front(&destruction_req), struct thread, elem);
        palloc_free_page(victim);
    }

    /* 파라미터 값으로 받은 Status를 적용한 뒤 Schedule() 호출 */
    thread_current()->status = status;
    schedule();
}

/* 실제로 스케쥴링을 처리하는 함수 */
static void schedule(void) {

    /* 현재 스레드와 다음 스레드를 정의 */
    struct thread *curr = running_thread();
    struct thread *next = next_thread_to_run();

    ASSERT(intr_get_level() == INTR_OFF);
    ASSERT(curr->status != THREAD_RUNNING);
    ASSERT(is_thread(next));

    /* 선정된 새로운 스레드의 status 값을 변경 */
    next->status = THREAD_RUNNING;

    /* 타임슬라이스 값을 초기화 */
    thread_ticks = 0;

#ifdef USERPROG

    /* 프로세스의 Address Space를 활성화 */
    process_activate(next);

#endif

    /* curr = next인 경우는 다음 작업을 수행하지 않도록 보호  */
    if (curr != next) {

        /* 현재 스레드가 DYING이고, Initial Thread가 아닌 경우에 한정 ; 삭제 대상 스레드 리스트에 추가 */
        if (curr && curr->status == THREAD_DYING && curr != initial_thread) {
            ASSERT(curr != next);
            list_push_back(&destruction_req, &curr->elem); // 현재 스레드가 실행 중이니 삭제해버리면 안되고, 리스트에 넣기만 함
        }

        /* 스위칭을 하기 전에, 현 스레드의 정보들을 임시로 저장해야 함 */
        thread_launch(next);
    }
}

/* 새로운 스레드 생성 시 부여되는 TID를 새로이 반환하는 함수 */
static tid_t allocate_tid(void) {
    static tid_t next_tid = 1;
    tid_t tid;

    lock_acquire(&tid_lock);
    tid = next_tid++;
    lock_release(&tid_lock);

    return tid;
}
