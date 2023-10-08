#include "userprog/exception.h"
#include "intrinsic.h"
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "userprog/gdt.h"
#include "userprog/process.h"
#include "userprog/syscall.h"
#include <inttypes.h>
#include <stdio.h>

/* 시스템이 처리한 Page Fault 숫자를 기록 */
static long long page_fault_cnt;

/* Static 함수 Prototyping */
static void kill(struct intr_frame *);
static void page_fault(struct intr_frame *);

/* Userprog가 일으킬 수 있는 Exception들을 다루는 Handler들을 초기화하는 함수.
   원문에서는 Interrupt라고 표현했는데, Interrupt (하드/소프트웨어)는 따로 Interrupt.c에서 다룸.
   필요하다면 [IA32-v3a]의 5.15파트에서 각 Interrupt/Exception 관련 설명을 찾아볼 수 있음.

   실제 OS들은 Exception들을 시그널의 형태로 유저 프로세스에게 전달할텐데 ([SV-386] 3-24, 3-25 참고),
   PintOS는 유저 프로세스를 그냥 Kill 시키도록 설계되어 있음.

   Page Fault는 Exception이지만, 추후에는 Virtual Memory를 포함하도록 다시 코드를 짜야 함.  */
void exception_init(void) {

    /* Exception들은 Userprogam에 의해서 Explicit 하게 직접 호출/발생할 수 있음.
       예컨대, INT, INT3, INTO, BOUND 등의 Instruction을 통해서 발생 가능.
       따라서 DPL==3으로 설정하여, 유저 프로그램들이 언급된 Instruction으로 호출할 수 있도록 함 */
    intr_register_int(3, 3, INTR_ON, kill, "#BP Breakpoint Exception");
    intr_register_int(4, 3, INTR_ON, kill, "#OF Overflow Exception");
    intr_register_int(5, 3, INTR_ON, kill, "#BR BOUND Range Exceeded Exception");

    /* 아래 Exception들은 DPL==0, 즉 유저 프로세스가 직접 호출할 수 없도록 함.
       단, 유저프로세스에 의해서 발생할수는 있음 (예컨대, 0으로 나눌 경우) */
    intr_register_int(0, 0, INTR_ON, kill, "#DE Divide Error");
    intr_register_int(1, 0, INTR_ON, kill, "#DB Debug Exception");
    intr_register_int(6, 0, INTR_ON, kill, "#UD Invalid Opcode Exception");
    intr_register_int(7, 0, INTR_ON, kill, "#NM Device Not Available Exception");
    intr_register_int(11, 0, INTR_ON, kill, "#NP Segment Not Present");
    intr_register_int(12, 0, INTR_ON, kill, "#SS Stack Fault Exception");
    intr_register_int(13, 0, INTR_ON, kill, "#GP General Protection Exception");
    intr_register_int(16, 0, INTR_ON, kill, "#MF x87 FPU Floating-Point Error");
    intr_register_int(19, 0, INTR_ON, kill, "#XF SIMD Floating-Point Exception");

    /* 대부분의 Exception들은 Interrupt를 켜두고 처리할 수 있지만,
       Page Fault는 %CR2에 저장된 Fault Address를 보존해야하기 떄문에 Interrupt를 꺼야함.
       OS는 %CR2에 저장된 값을 기반으로 Page Fault를 어떻게 처리할지 결정하게 됨. */
    intr_register_int(14, 0, INTR_OFF, page_fault, "#PF Page-Fault Exception");
}

/* Exception 관련된 통계들을 출력하는 함수. */
void exception_print_stats(void) { printf("Exception: %lld page faults\n", page_fault_cnt); }

/* Exception을 처리하는 실제 Handler 함수 (유저 프로그램에 의해서 발생할 가능성이 높음).
   Unmapped VM (page fault) 등.. PintOS는 문제가 되는 모든 프로그램들을 종료시킴.
   추후에는 Page Fault들을 Kernel에서 처리할 수 있도록 코드를 수정해야 함.
   Kernel 레벨에서 발생하는 Exception이 있다면 System Panic이 발생함.
   좀더 공부하자면.. Page Fault가 커널 Exception을 일으킬 수 있으나, 현재 Scope에서는 무관함. */
static void kill(struct intr_frame *f) {

    /* Parameter로 제공된 intr_frame의 Code Segment Value를 통해 Exception 발생 위치를 파악 */
    switch (f->cs) {

    case SEL_UCSEG:
        /* Exception이 유저 Code에서 발생한 Case일 경우 - 프로세스 킬 */
        printf("%s: dying due to interrupt %#04llx (%s).\n", thread_name(), f->vec_no, intr_name(f->vec_no));
        intr_dump_frame(f);
        thread_exit();

    case SEL_KCSEG:
        /* Exception이 커널 Code에서 발생했을 경우 - 커널 패닉 */
        intr_dump_frame(f);
        PANIC("Kernel bug - unexpected interrupt in kernel");

    default:
        /* 여기까지 오면 안됨 - 다른 코드 세그먼트에서 문제가 발생했다는 뜻이니, 패닉 Invoke */
        printf("Interrupt %#04llx (%s) in unknown segment %04x\n", f->vec_no, intr_name(f->vec_no), f->cs);
        thread_exit();
    }
}

/* Page Fault를 처리하는 Handler. 이 코드는 단순 뼈대일 뿐이며, Virtual Memory를 고려하도록 수정되어야 함.
   Project 2를 하기 위해서도 일부 수정이 필요할 수 있음.

   위에도 코멘트 했지만, 문제가 되는 주소는 %CR2에 저장됨 (Control Register 2).
   Fault와 관련된 정보들은 exceptions.h의 PF_P, PF_W, PF_U 참고 요망.
   Fault와 관련된 정보들은 intr_frame의 error_code 멤버로 저장됨.

   현재 제공되는 예시/뼈대 코드는 intr_frame에 저장된 정보를 Parse하는 방법을 설명함.
   [IA32-v3a] 5.15에서 "Interrupt 14" 관련 내용을 읽어보면 좋음. */
static void page_fault(struct intr_frame *f) {

    bool not_present; /* True: not-present page, false: writing r/o page. */
    bool write;       /* True: access was write, false: access was read. */
    bool user;        /* True: access by user, false: access by kernel. */
    void *fault_addr; /* Fault address. */

    /* Faulting Address를 확보 (Virtual Address).
       특정 코드 또는 데이터를 가리킬 수 있으며, 반드시 Instruction을 가리키진 않음.
       Instruction은 현 시점에서 f->rip에 저장되어 있음. */
    fault_addr = (void *)rcr2();

    /* Exceptions.c에서 다른 코멘트로도 언급했지만, Page Fault는 Interrupt를 끄고 다뤄야 함.
       %cr2에서 필요한 정보가 바뀌기 전에 확보하기 위한 절차였으니, 이제 켜줘도 됨. */
    intr_enable();

    /* Page Fault가 발생한 이유를 확인 */
    not_present = (f->error_code & PF_P) == 0;
    write = (f->error_code & PF_W) != 0;
    user = (f->error_code & PF_U) != 0;

#ifdef VM
    /* For project 3 and later. */
    if (vm_try_handle_fault(f, fault_addr, user, write, not_present))
        return;
#endif

    /* 발생한 Page Fault의 숫자를 증감 (통계 관리 목적) */
    page_fault_cnt++;  
    exit(-1);
    /* 만일 Fault가 진짜 에러로 발생한 Fault라면, 관련 정보를 보여주고 프로세스를 종료. */
    printf("Page fault at %p: %s error %s page in %s context.\n", fault_addr, not_present ? "not present" : "rights violation", write ? "writing" : "reading", user ? "user" : "kernel");
    kill(f);
}
