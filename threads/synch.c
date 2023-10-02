/* Nachos OS 소스코드를 참고해서 제작됨 (Copyright 관련 문구는 삭제했으니 필요하면 원문 참고 요망) */

#include "threads/synch.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include <stdio.h>
#include <string.h>

////////////////////////////////////////////////////////////////////////////////
//////////////////////////////// Semaphores ////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* Sema_down & _up 에서 waiters 리스트 삽입에 활용되는 보조 함수 */
bool priority_comparison(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED) {
    struct thread *t_new = list_entry(new, struct thread, elem);
    struct thread *t_existing = list_entry(existing, struct thread, elem);

    return t_new->priority > t_existing->priority;
}

/* Semaphore 활용을 위해서 필요한 초기화 작업을 수행하는 함수 */
void sema_init(struct semaphore *sema, unsigned value) {

    ASSERT(sema != NULL);

    sema->value = value; // unsigned (synch.h 참고)
    list_init(&sema->waiters);
}

/* Semaphore에 down/P 작업을 수행하는 함수. */
void sema_down(struct semaphore *sema) {

    /* value가 양의 숫자가 될 때 까지 스레드를 Block하기 때문에 Interrupt Handler에서 수행 불가 */
    ASSERT(sema != NULL);
    ASSERT(!intr_context());

    enum intr_level old_level = intr_disable();
    struct thread *curr = thread_current();

    /* value가 0일 경우 무한정 대기 */
    while (sema->value == 0) {
        // list_push_back(&sema->waiters, &thread_current()->elem);
        list_insert_ordered(&sema->waiters, &curr->elem, priority_comparison, NULL);
        thread_block();
    }

    /* value가 양의 숫자가 되는 순간 해당 semaphore를 확보. */
    sema->value--;
    intr_set_level(old_level);
}

/* sema_down을 시도 ; 성공시 true, 실패한다면 false를 반환하는 응용함수.
   Interrupt Handler에서도 호출 가능 (thread_block() 없음). */
bool sema_try_down(struct semaphore *sema) {

    ASSERT(sema != NULL);

    enum intr_level old_level = intr_disable();
    bool success;

    if (sema->value > 0) {
        sema->value--;
        success = true;
    } else
        success = false;

    intr_set_level(old_level);
    return success; // success라는 변수지만, true/fail을 담고 있으니 햇갈리면 안됨
}

/* Semaphore에 up/V 작업을 수행하는 함수 (Interrupt Handler에서 호출 가능).
   value가 양의 숫자가 되기를 기다리고 있는 단일 스레드를 깨우는 역할 */
void sema_up(struct semaphore *sema) {

    ASSERT(sema != NULL);

    enum intr_level old_level = intr_disable();

    if (!list_empty(&sema->waiters)) {
        list_sort(&sema->waiters, priority_comparison, NULL); // priority 가 큰 순서대로 정렬
        thread_unblock(list_entry(list_pop_front(&sema->waiters), struct thread, elem));
    }

    sema->value++;        // 대기중인 스레드가 있다면 : 여기서 sema_up으로 value를 1로 바꾸고, unblock된 waiter가 다시 값을 내리게 됨
    thread_check_yield(); // 현재 thread의 priority와 ready_list의 priority를 비교하여 yield
    intr_set_level(old_level);
}

/* Semaphore를 위한 자체 테스트 기능 (디버깅 목적 ; sema를 '핑퐁' 하는 함수) */
static void sema_test_helper(void *sema_) {
    struct semaphore *sema = sema_;
    int i;

    for (i = 0; i < 10; i++) {
        sema_down(&sema[0]);
        sema_up(&sema[1]);
    }
}
void sema_self_test(void) {
    struct semaphore sema[2];
    int i;

    printf("Testing semaphores...");
    sema_init(&sema[0], 0);
    sema_init(&sema[1], 0);
    thread_create("sema-test", PRI_DEFAULT, sema_test_helper, &sema);
    for (i = 0; i < 10; i++) {
        sema_up(&sema[0]);
        sema_down(&sema[1]);
    }
    printf("done.\n");
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////////////// Locks ///////////////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* Lock 관련 우선순위 donation 과정에서 donation list에 값을 넣기 위한 보조함수 */
bool donate_priority_comparison(const struct list_elem *new, const struct list_elem *existing, void *aux UNUSED) {
    struct thread *t_new = list_entry(new, struct thread, donation_elem);
    struct thread *t_existing = list_entry(existing, struct thread, donation_elem);

    return t_new->priority > t_existing->priority;
}

/* Lock을 초기화 하는 함수 (구현된 락은 반복적으로 확보될 수 없음 ; 단일 스레드 전용 락).
   조지아텍 강의에서 언급된 것 처럼, 가장 원시적인 락은 Semaphore 값을 1로 가지는 형태.
   락을 보유한 스레드만 해당 락의 sema 값을 올리거나 내릴 수 있어야 함. */
void lock_init(struct lock *lock) {
    ASSERT(lock != NULL);

    lock->holder = NULL;
    sema_init(&lock->semaphore, 1);
}

/* Lock을 확보하는 함수 (확보 못하면 Blocked 상태로 전환, 필요시 우선순위 Donation).
   Block 상태가 될 수 있기 때문에 Interrupt Handler에서 호출하면 안됨.
   Semphore 함수 설명에도 언급했지만, PintOS Lock은 반복적으로 복수의 사람들이 확보할 수 없음.
   함수 내에서 Interrupt를 끌 수도 있으나, Block 상태 진입 전에 다시 활성화 필요. */
void lock_acquire(struct lock *lock) {

    /* 필요조건 충족 여부 확인 */
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(!lock_held_by_current_thread(lock));

    /* Lock을 다른 스레드가 소유하고 있다면, */
    if (lock->holder) {

        /* 현재 스레드의 struct 멤버 값을 갱신 */
        struct thread *cur = thread_current();
        cur->waiting_for_lock = lock;

        /* 현재 스레드의 donation_elem을 lock 소유자의 donation 리스트에 삽입  */
        list_insert_ordered(&lock->holder->donations, &cur->donation_elem, donate_priority_comparison, NULL);

        /* 반복문으로 꼬리물듯이 waiting_for_lock이 없을 때 까지 우선순위 donate (donation_elem은 내가 대기중인 스레드에만 제공) */
        while (cur->waiting_for_lock) {
            struct thread *holder = cur->waiting_for_lock->holder;
            holder->priority = cur->priority;
            cur = holder;
        } /* 중요 : Donation 리스트는 사실상 해당 락을 기다리고 있는 스레드를 기록하는 역할 */
    }

    sema_down(&lock->semaphore);               // 락 홀더가 없다면 바로 성공, 아니라면 Block 상태로 진입
    thread_current()->waiting_for_lock = NULL; // 결국 sema_down을 성공했으니, 락을 acquire하는데 성공한 것
    lock->holder = thread_current();
}

/* Lock acquire를 시도하되, 성공하면 true, 실패하면 False를 반환.
   sema_try_down()의 응용이며, 성공시 lock->holder 자동으로 업데이트.
   Interrupt Handler에서도 사용할 수 있음. */
bool lock_try_acquire(struct lock *lock) {

    ASSERT(lock != NULL);
    ASSERT(!lock_held_by_current_thread(lock));

    bool success = sema_try_down(&lock->semaphore); // sema_try_down() 실패시 'false', 성공시 'true'
    if (success)
        lock->holder = thread_current();

    return success;
}

/* Lock을 풀어주는 함수 (현재 소유한 락이어야 함). */
void lock_release(struct lock *lock) {

    ASSERT(lock != NULL);
    ASSERT(lock_held_by_current_thread(lock));

    struct thread *cur = thread_current();

    /* lock을 기다리며 donation 리스트를 순회, 해당 락을 기다리던 모든 스레드의 donation_elem을 리스트에서 제거 */
    struct list_elem *e;
    for (e = list_begin(&cur->donations); e != list_end(&cur->donations); e = list_next(e)) {
        struct thread *t = list_entry(e, struct thread, donation_elem);
        if (t->waiting_for_lock == lock)
            list_remove(&t->donation_elem);
    }

    /* 현재 우선순위를 원래 우선순위로 원복 */
    cur->priority = cur->priority_original;

    /* donation list가 여전히 내용물이 있다면, 다른 락을 들고 있다는 뜻 */
    if (!list_empty(&cur->donations)) {

        /* 따라서 donation_list를 우선순위에 따라서 다시 한번 정렬해주고, */
        list_sort(&cur->donations, donate_priority_comparison, NULL);

        /* 제일 우선순위 높은 스레드를 찾은 뒤, 해당 스레드의 우선순위가 나보다 높다면 내가 우선순위를 승계 */
        struct thread *front = list_entry(list_front(&cur->donations), struct thread, donation_elem);
        if (front->priority > cur->priority)
            cur->priority = front->priority;
    }

    /* 릴리즈에 성공했으니, 해당 락의 소유주 정보를 제거하고 Semaphoare value도 올려줘야 함 */
    lock->holder = NULL;
    sema_up(&lock->semaphore);
}

/* 현재 스레드가 해당 락의 소유주인지 확인하는 함수.
   맞다면 true, 아니라면 false 반환 */
bool lock_held_by_current_thread(const struct lock *lock) {

    ASSERT(lock != NULL);

    return lock->holder == thread_current();
}

////////////////////////////////////////////////////////////////////////////////
///////////////////////////// Conditional Variables ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* List에 삽입 가능한 형태로 semaphore를 감싸주는 일종의 컨테이너 역할 (Wrapper). */
struct semaphore_elem {
    struct list_elem elem;      // 리스트에 넣기 위한 elem
    struct semaphore semaphore; // 실제 semaphore
};

/* cond_wait() & signal()에서 리스트 삽입을 돕기 위한 보조 함수 */
bool sema_priority_comparison(const struct list_elem *a_, const struct list_elem *b_, void *aux UNUSED) {
    struct semaphore_elem *a = list_entry(a_, struct semaphore_elem, elem);
    struct semaphore_elem *b = list_entry(b_, struct semaphore_elem, elem);
    struct list *waiter_a_sema = &(a->semaphore.waiters);
    struct list *waiter_b_sema = &(b->semaphore.waiters);

    return list_entry(list_begin(waiter_a_sema), struct thread, elem)->priority > list_entry(list_begin(waiter_b_sema), struct thread, elem)->priority;
}

/* struct condition (synch.h)를 초기화.
   아주 기본적인 condVar는 특정 코드가 시그널을 주면, 협조하는 코드가 수행될 수 있도록 하는 구조 */
void cond_init(struct condition *cond) {
    ASSERT(cond != NULL);

    /* PintOS에서 struct cond는 struct list waiters 단 하나의 멤버만 보유 */
    list_init(&cond->waiters);
}

/* 락을 확보 한 상태에서, 특정 컨디션이 충족 되어 signal을 받기 전까지 락을 풀고 대기.
   해당 시그널을 받으면 깨어나서 다시 락을 확보하는 구조.
   Atomic하게 실행되는 함수 ; 해당 코드가 방해 없이 끝까지 쭉 실행된다는 의미.
   단, Hoare 가 아닌 Mesa 스타일 ; 즉, 시그널을 주고 받는 과정은 Atomic 하지 않음.
   따라서 cond_wait을 호출하는 사람이 해당 컨디션이 충족되었는지 확인 후 wait()을 다시 호출해야 함.
   마찬가지로 특정 컨디션이 충족되면 explicit하게 시그널 또는 브로드캐스트를 줘야 함.
   하나의 락에 여러개의 conditional variable이 연계되어 운영될 수 있음.
   이 함수는 blocked 상태로 진입할 수 있기 때문에 Interrupt Handler가 호출하면 안됨. */
void cond_wait(struct condition *cond, struct lock *lock) {

    struct thread *curr = thread_current();

    /* cond_wait()을 실행하기 위한 전용 semaphore_elem 선언 (waiters에 삽입되니 waiters로 명명) */
    struct semaphore_elem waiter;

    /* 함수 실행을 위한 조건들을 충족하는지 확인 */
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    /* cond_wait()을 실행하기 위한 전용 sema를 선언 */
    sema_init(&waiter.semaphore, 0);

    /* condition의 멤버인 waiters에 새로 생성한 waiter의 elem을 우선순위에 따라 추가 */
    list_insert_ordered(&cond->waiters, &waiter.elem, sema_priority_comparison, NULL);

    /* 현재 스레드끼리 경쟁중인 락을 릴리즈 하고, cond_signal/broadcast()가 해당 waiter.semaphore를 1로 만들떄 까지 대기 */
    lock_release(lock);
    sema_down(&waiter.semaphore);

    /* sema_down()에 성공했으니 락 확보 */
    lock_acquire(lock);
}

/* If any threads are waiting on COND (protected by LOCK), then
   this function signals one of them to wake up from its wait.
   LOCK must be held before calling this function.

   An interrupt handler cannot acquire a lock, so it does not
   make sense to try to signal a condition variable within an
   interrupt handler. */

/* 특정 cond_wait() 중인 스레드에게 시그널을 주는 대응 함수 (a pair) */
void cond_signal(struct condition *cond, struct lock *lock UNUSED) {

    ASSERT(cond != NULL);
    ASSERT(lock != NULL);
    ASSERT(!intr_context());
    ASSERT(lock_held_by_current_thread(lock));

    /* cond의 waiters (유일한 멤버) 리스트가 비어있지 않다면, */
    if (!list_empty(&cond->waiters)) {

        /* 해당 리스트를 우선순위에 따라 한번 졍렬한 뒤 제일 우선순위 높은 waiter의 sema를 상향 조정 */
        list_sort(&cond->waiters, sema_priority_comparison, NULL);
        /* cond->waiters에 있는 하나의 waiter(semaphore_elem의 elem)을 뽑아서 -> semaphore_elem으로 전환한 뒤, 실제 semaphore로 진입 (child-parent-diff.child) -> sema_up() 실행 */
        sema_up(&list_entry(list_pop_front(&cond->waiters), struct semaphore_elem, elem)->semaphore);
    }
}

/* cond->waiters의 모든 구성원들에게 cond_signal을 날리는 함수. */
void cond_broadcast(struct condition *cond, struct lock *lock) {
    ASSERT(cond != NULL);
    ASSERT(lock != NULL);

    while (!list_empty(&cond->waiters))
        cond_signal(cond, lock);
}
