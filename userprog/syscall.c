#include "userprog/syscall.h"
#include "filesys/file.h"
#include "filesys/filesys.h" // 32-bit filesys 버그 해결
#include "intrinsic.h"
#include "threads/flags.h"
#include "threads/interrupt.h"
#include "threads/loader.h"
#include "threads/palloc.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/gdt.h"
#include "userprog/process.h" // 관련 파일 헤더들 전부 연결
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
pid_t fork(const char *thread_name, struct intr_frame *f);
int exec(const char *cmd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
int write(int fd, const void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

/* File Descriptor 관련 함수 Prototype & Global Variables */
int allocate_fd(struct file *file);
struct file *get_file_from_fd(int fd);
void release_fd(int fd);
void close_file(int fd);
// fd_table_destroy는 syscall.h로 이동

struct semaphore filesys_sema; // 파일시스템 동기화를 위한 세마포어

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
    sema_init(&filesys_sema, 1);
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
        halt();

    case SYS_EXIT:
        exit(f->R.rdi);
        break;

    case SYS_FORK:
        f->R.rax = fork(f->R.rdi, f);
        break;

    case SYS_EXEC:
        f->R.rax = exec(f->R.rdi);
        break;

    case SYS_WAIT:
        f->R.rax = wait(f->R.rdi);
        break;

    case SYS_CREATE:
        f->R.rax = create(f->R.rdi, f->R.rsi);
        break;

    case SYS_REMOVE:
        f->R.rax = remove(f->R.rdi);
        break;

    case SYS_OPEN:
        f->R.rax = open(f->R.rdi);
        break;

    case SYS_FILESIZE:
        f->R.rax = filesize(f->R.rdi);
        break;

    case SYS_READ:
        f->R.rax = read(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_WRITE:
        f->R.rax = write(f->R.rdi, f->R.rsi, f->R.rdx);
        break;

    case SYS_SEEK:
        seek(f->R.rdi, f->R.rsi);
        break;

    case SYS_TELL:
        f->R.rax = tell(f->R.rdi);
        break;

    case SYS_CLOSE:
        close(f->R.rdi);
        break;

    default:
        printf("Unknown system call: %d\n", syscall_num); // deprecated by placeholder, but kept in place
        thread_exit();
    }

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
        return false; // pml4만 확인하는 함수 (나머지 레벨의 page table 들도 검사해야하는데, 우선 이렇게)

    /* 다 통과했으니 */
    return true;
}

/* 유저에게 전달받은 버퍼의 처음과 끝, 그리고 다시 중간을 검사하는 함수 (특히, 버퍼가 커서 복수의 페이지를 사용하는 경우) */
bool buffer_validity_check(void *buffer, unsigned size) {

    /* buffer의 최초 주소 (시작 주소)를 확인 */
    if (!pointer_validity_check(buffer))
        return false;

    /* buffer의 마지막 주소를 확인 */
    if (!pointer_validity_check(buffer + size - 1)) // GPT한데 코드를 확인받아보니, buffer+size가 딱 페이지의 끝일 경우 0으로 돌아가기 때문에 -1을 추천
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

/* power_off()를 호출해서 PintOS를 꺼버리는 함수.
   가급적 사용되지 말아야함 (디버깅이 필요한 특정 상황들에서 정보를 날릴 수도 있음). */
void halt(void) { power_off(); }

/* 현재 구동되던 유저 프로그램을 종료시키고, 커널로 Status값을 돌려주는 시스템콜.
   만일 프로세스의 Parent가 기다리고 있다면 status 값이 parent에게 전달됨.
   전통적으로 0은 Success, nonzero value는 실패를 의미함 (return). */
void exit(int status) {

    // sema_down(&filesys_sema);
    /* 테스트 통과용 printf */
    printf("%s: exit(%d)\n", thread_current()->name, status); // 이걸 process_exit()으로 옮기면 syn-read가 조금 더 진행됨 (;;)

    /* 유저 프로그램이 직접 제공한 status 값을 exit 하는 프로세스/스레드의 exit_status 값으로 저장 */
    thread_current()->exit_status = status;

    /* open()에서 파일의 작성 권한을 제한했으니, 이제 같은 이름의 프로그램이 없어진다면 file_allow_write를 해줘야 함 */
    // 단, 파일을 재대로 닫아주기만 했다면 권한은 다시 자동으로 복구되니.. 문제의 소지는 있으나 일단 코멘트만 유지

    /* 스레드 죽이기 */
    thread_exit();
}

/* 현재 프로세스의 클론인 'thread_name'이라는 새로운 프로세스를 만드는 함수.
   RBX, RSP, RBP, R12-15 이외에는 레지스터 값을 복제할 필요 없음 (callee-saved registers).
   Child 프로세스는 file descriptor와 virtual memory 등을 전부 복제해야 하며, fork()의 리턴값은 0이 되어야 함.
   Parent 프로세스는 child의 클론이 마무리될 때까지 fork()에서 탈출하면 안됨 ; 리소스 복제에 실패할 경우 fork()는 TID_ERROR를 반환해야 함.
   기본적으로 pml4_for_each()로 메모리와 페이지테이블 구조를 복제하지만, 이 함수에 들어갈 func를 작성해야 함 (duplicate_pte). */
pid_t fork(const char *thread_name, struct intr_frame *snapshot) {

    if (!pointer_validity_check(thread_name))
        return false;

    /* 시스템콜이 발생한 시점의 Parent intr_frame을 저장하고 process_fork로 전달 */
    pid_t pid = process_fork(thread_name, snapshot);

    /* 만일 포크가 실패한다면 */
    if (pid == TID_ERROR) {
        return TID_ERROR;
    }

    /* 포크 성공! ; do_fork에서 child의 %Rax 값을 0으로 만들어줬기 때문에 리턴값은 자동으로 처리됨 */
    return pid;
}

/* 현재 구동중인 프로세스를 cmd_line이라는 이름을 가진 executable로 바꾸는 함수 (switch execution state of same process).
   성공하면 리턴값이 없고, 실패시 exit state -1으로 종료됨 ; exec을 부른 스레드의 이름을 바꾸는게 아니고, 열려있는 파일들은 유지됨. */
int exec(const char *cmd_line) {

    /* 전달받은 cmd_line 값 (파일명 + argv)을 복사 */
    char *cmd_line_copy;
    cmd_line_copy = palloc_get_page(0);
    if (cmd_line_copy == NULL) {
        exit(-1);
    }
    strlcpy(cmd_line_copy, cmd_line, PGSIZE);

    /* Process Exec을 불러서 실패시 에러 반환 */
    if (process_exec(cmd_line_copy) == -1) {
        exit(-1);
    }
    // palloc_free_page(cmd_line_copy);    
    /* Debug ; 성공시 다음 값이 출력되면 안됨 */
    printf("exec() implementation failed (should never print this or return -1)\n");
}

/* 제공되는 child의 pid를 기준으로 무기한 대기하는 함수 ; 타겟 child가 종료되면 exit_status를 리턴.
   만일 pid가 직접 exit()을 하지 않을 경우 (커널이 종료시키는 등), wait()은 여전히 통과해서 -1을 반환해야 함.
   이미 사망한 child를 parent가 wait하는 경우가 있을 수 있으나, 커널이 여전히 사망 원인 (exit_status)를 돌려주 수 있어야 함.
   다음 2가지 경우에는 wait가 무조건 실패:
      (1) PID가 호출한 parent의 자식이 아님 ; 손자는 자식이 아니며, 손자를 기다릴 수 없음.
      (2) 같은 프로세스가 동일 pid에 두번 wait를 걸 수 없음 ; 하나의 프로세스는 하나의 자식을 한번만 기다릴 수 있음. */
int wait(pid_t pid) {

    /* 재대로 된 pid가 아니라면 거절 */
    if (pid < 0) {
        return -1; // Invalid PID.
    }

    return process_wait(pid);
}

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

/* 'file'이라는 이름을 가진 파일을 삭제하는 함수. 성공하면 True, 실패는 False.
   파일은 Open/Close와 무관하게 삭제될 수 있으며, 파일을 자동으로 닫지 않음. */
bool remove(const char *file) {

    if (!pointer_validity_check(file)) {
        exit(-1);
    }

    bool success = false;

    /* filesys.c 참고 ; create()와 동일 */
    success = filesys_remove(file);

    return success;
}

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
    // sema_down(&filesys_sema);
    struct file *opened_file;

    opened_file = filesys_open(file); // *file의 주소 file

    // sema_up(&filesys_sema);

    if (!opened_file){

        // sema_up(&filesys_sema);
        return -1;
    }

    // /* 스레드 이름에 \000 문자열이 자꾸 반복적으로 들어가서, 여기서 혹시 모르니 한번 수동 처리... */
    // char *weird_thread_name = thread_current()->name;
    // char *better_thread_name = malloc(strlen(weird_thread_name) + 1); // +1 for null terminator
    // int i, j = 0;
    // for (i = 0; i < strlen(weird_thread_name); i++) {
    //     if (weird_thread_name[i] != '\0') {
    //         better_thread_name[j++] = weird_thread_name[i];
    //     }
    // }
    // better_thread_name[j] = '\0';

    // /* 만일 파일이 실행중이라면 수정 금지 */
    // if (strcmp(better_thread_name, file) == 0)
    //     file_deny_write(opened_file);
    // free(better_thread_name);

    /* 만일 파일이 실행중이라면 수정 금지 */
    if (strcmp(thread_current()->name, file) == 0) {
        file_deny_write(opened_file);
    }

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

/* fd로 열린 파일의 파일 크기를 반환 */
int filesize(int fd) {

    /* fd 값을 검증하는 과정이 있으면 좋겠는데, 우선 스킵 */

    /* fd에서 파일을 찾아서, */
    struct file *file = get_file_from_fd(fd); // 여기서 fd 2~256을 검증하긴 함

    /* 해당 파일을 검증 */
    if (!file) {
        return -1; // or set an appropriate error code
    }

    // Return the file's size
    return file_length(file);
}

/* 'size' 바이트 만큼 열린 파일 fd에서 read를 실행, buffer에 저장하는 함수.
   함수 리턴값은 실제로 읽기에 성공한 바이트 수, 또는 실패시 -1.
   fd 0은 input_getc()를 통해서 키보드 입력값을 읽어옴. */
int read(int fd, void *buffer, unsigned size) {

    if (!buffer_validity_check(buffer, size)) {

        exit(-1);
    }
    /* 읽어온 바이트 수를 기록할 변수 초기화 */
    int read_count = 0;
    // sema_down(&filesys_sema);
    /* fd = 0의 케이스 처리 ; input_getc()는 글자를 하나씩 읽어서 리턴하는 함수 (input.c) */
    if (fd == 0) {
        for (unsigned int i = 0; i < size; i++) {
            ((unsigned char *)buffer)[i] = input_getc();
            read_count++;
        }
        // sema_up(&filesys_sema);
        return read_count;
    }

    /* fd = 0이 아닐 경우 */
    struct file *file = get_file_from_fd(fd);
    if (!file){
        // sema_up(&filesys_sema);
        return -1; // exit(-1)을 하려다가, 공식 문서에 적힌대로 우선 -1로 바꾼 상태
    }
    read_count = file_read(file, buffer, size); // file_read는 size를 (off_t*) 형태로 바라는 것 같은데, 에러가 떠서 일단 일반 사이즈로 넣음
    
    // sema_up(&filesys_sema);
    return read_count;
}

/* Open된 file fd에서 'size' 바이트만큼 'buffer'에 저장하는 시스템콜.
   성공시 Write한 바이트 크기를 반환하며, 요청보다 적을 수 있음.
   보통 End-of-file을 넘어서서 작성하게 될 경우 파일 크기가 커져야 하지만,
   PintOS에 제공되는 기본 파일시스템은 이 기능을 지원하지 않음.
   따라서 EoF까지 최대한 작성한 뒤에 성공한 글자 수를 반환하게 됨.
   fd == 1은 시스템 콘솔에 작성하는 Shortcut (테스트용).
   시스템 콘솔에 write하기 위한 코드는 buffer에 있는 모든 데이터를 putbuf()로 한번에 사용해야 함 (수백바이트 크기가 아니라면).
   한번에 putbuf()를 하지 않는다면 다양한 프로세스들의 아웃풋이 콘솔에 혼재되어 프린트되게 됨. */
int write(int fd, const void *buffer, unsigned size) {

   
    // sema_down(&filesys_sema);
    if (fd == 0) {

        return -1; // STDIN
    }

    if (!buffer_validity_check(buffer, size)) {
        exit(-1); // Validity 확인 결과 실패
    }
    // sema_down(&filesys_sema);
    if (fd == 1) {
        putbuf(buffer, size);
        // sema_up(&filesys_sema);
        return size; // STDOUT
    }

    struct file *file_to_write = get_file_from_fd(fd);
    if (!file_to_write) {
        // sema_up(&filesys_sema);
        return -1; // fd로 파일 가져오기 실패
    }

    if (file_to_write->deny_write == true) {
        // sema_up(&filesys_sema);
        return NULL;
    } // 만일 deny_write라면 실패 반환 (임시, sync_write 등에서 수정 필요할 가능성 높음)

    
    int bytes_written = file_write(file_to_write, buffer, size);
    
    // sema_up(&filesys_sema);

    return bytes_written;
}

/* 열려있는 파일 fd에서 아래의 tell()위치를 'position'에 담아서 반환하는 함수.
   Project 4 이후에야 신경을 써야 하는 함수 (그 전까지는 file system이 자체적으로 관련 에러 처리 가능).
   구체적으로는, seek로 read를 할 경우 EoF에서 0을 반환 (시작점), write를 할 경우 파일을 extend해야 함. */
void seek(int fd, unsigned position) {

    struct file *file = get_file_from_fd(fd);
    if (!file) {
        return;
    }

    file_seek(file, position);
}

/* 열려있는 파일 fd에서 to-be-read 또는 to-be-written인 다음 바이트의 위치를 반환하는 함수 (파일의 시작 위치부터 Offset of Bytes로 표현).  */
unsigned tell(int fd) {

    struct file *file = get_file_from_fd(fd);
    if (!file) {
        return;
    }

    return file_tell(file);
}

/* fd로 대변되는 파일을 닫는 함수. 프로세스의 종료는 관련된 fd를 전부 닫는 효과가 있음 (이 함수를 여러번 호출하는 것과 동일한 효과). */
void close(int fd) {

    struct thread *t = thread_current();

    /* 탐색해서 맞는 fd를 닫음 */
    if (2 <= fd && fd <= 256) {
        lock_acquire(&t->fd_lock);
        close_file(fd);
        lock_release(&t->fd_lock);
    }
}

////////////////////////////////////////////////////////////////////////////////
////////////////////////// File Descriptor 전용 함수들 ////////////////////////////
////////////////////////////////////////////////////////////////////////////////

/* init_thread()에서 palloc 으로 struct thread userprog의 struct file **fd_table을 초기화 했음 */

/* fd 번호를 새로 allocate 하는 함수 */
int allocate_fd(struct file *file) {

    struct thread *t = thread_current(); // user thread는 in the kernel이 된 상태 ; kernel thread가 아님

    lock_acquire(&t->fd_lock);
    /* init_thread()에서 palloc된 페이지를 탐색, 0으로 채워진 공간을 확보 */
    for (int i = 2; i < 256; i++) { // fd 0과 1번은 stdin stdout 전용이니 건너뛰어야 함 ; palloc 공간은 더 크지만 그냥 fd 개수는 256으로 제한
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

    if (fd >= 2 && fd < 256) {
        return t->fd_table[fd];
    }
    return NULL; // Invalid fd
}

/* fd번호에 해당하는 공간을 0으로 다시 되돌리는 함수 */
void release_fd(int fd) {

    struct thread *t = thread_current();

    if (fd >= 2 && fd < 256) {
        t->fd_table[fd] = 0;
    }
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

    lock_acquire(&t->fd_lock);
    for (int i = 2; i < 256; i++) {
        if (t->fd_table[i]) {
            // file_allow_write(t->fd_table[i]);
            file_close(t->fd_table[i]);
            t->fd_table[i] = 0;
        }
    }
    lock_release(&t->fd_lock);
    
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