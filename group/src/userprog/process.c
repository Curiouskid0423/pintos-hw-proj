#include "userprog/process.h"
#include "list.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "userprog/gdt.h"
#include "userprog/pagedir.h"
#include "userprog/tss.h"
#include "filesys/directory.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/flags.h"
#include "threads/init.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"

// static struct semaphore temporary;
static thread_func start_process NO_RETURN;
static bool load(const char* file_name, void (**eip)(void), void** esp);

const int MAX_ARGS = 100;

/* Initializes user programs in the system by ensuring the main
   thread has a minimal PCB so that it can execute and wait for
   the first user process. Any additions to the PCB should be also
   initialized here if main needs those members */
void userprog_init(void) {
  struct thread* t = thread_current();
  bool success;

  /* Allocate process control block
     It is imoprtant that this is a call to calloc and not malloc,
     so that t->pcb->pagedir is guaranteed to be NULL (the kernel's
     page directory) when t->pcb is assigned, because a timer interrupt
     can come at any time and activate our pagedir */
  t->pcb = calloc(sizeof(struct process), 1);
  success = t->pcb != NULL;

  /* Kill the kernel if we did not succeed */
  ASSERT(success);
  /* Initialize children_list for the MOTHER PROG */
  list_init(&(t->pcb->children_list));
}

typedef struct fn_wrapper {
  char* fn_copy;
  struct dir* cwd;
  pc_shared_t* shared;
} fn_wrapper_t;

/* Starts a new thread running a user program loaded from
   FILENAME.  The new thread may be scheduled (and may even exit)
   before process_execute() returns.  Returns the new process's
   process id, or TID_ERROR if the thread cannot be created. */
pid_t process_execute(const char* file_name) {
  char* fn_copy;
  tid_t tid;
  struct thread* t = thread_current();

  fn_wrapper_t* fn_wrapper = (fn_wrapper_t*)malloc(sizeof(fn_wrapper_t));
  // TODO: check the return type/value
  if (fn_wrapper == NULL) {
    return -1;
  }

  /* Initialize shared struct */
  pc_shared_t* shared = (pc_shared_t*)malloc(sizeof(pc_shared_t));
  if (shared == NULL) {
    return -1;
  }

  shared->ref_cnt = 2;
  shared->exit_code = -1;
  sema_init(&(shared->exec_sema), 0);
  sema_init(&(shared->wait_sema), 0);
  lock_init(&(shared->ref_cnt_lock));

  /* Make a copy of FILE_NAME.
     Otherwise there's a race between the caller and load(). */
  fn_copy = palloc_get_page(0);
  if (fn_copy == NULL)
    return TID_ERROR;
  strlcpy(fn_copy, file_name, PGSIZE);

  fn_wrapper->fn_copy = fn_copy;
  fn_wrapper->cwd = t->pcb->curr_work_dir;
  fn_wrapper->shared = shared;

  // Initialize additional char* for strtok_r
  char* executable_name = (char*)malloc(sizeof(char) * (strlen(file_name) + 1));
  strlcpy(executable_name, file_name, strlen(file_name) + 1);
  // So output of tests will include only the executable's name
  file_name = strtok_r(executable_name, " ", &executable_name);

  /* Create a new thread to execute FILE_NAME. */
  tid = thread_create(file_name, PRI_DEFAULT, start_process, fn_wrapper);
  if (tid == TID_ERROR)
    palloc_free_page(fn_copy);

  sema_down(&(shared->exec_sema));

  if (shared->child_pid != -1) {
    shared->child_pid = tid;
    list_push_back(&(t->pcb->children_list), &(shared->elem));
  } else {
    tid = -1;
    free(shared);
  }

  return tid;
}

/* A thread function that loads a user process and starts it
   running. */
static void start_process(void* file_name_) {
  fn_wrapper_t* fn_ = (fn_wrapper_t*)file_name_;
  char* file_name = (char*)fn_->fn_copy;
  pc_shared_t* shared = (pc_shared_t*)fn_->shared;
  struct thread* t = thread_current();
  struct intr_frame if_;
  bool success, pcb_success;

  /* Allocate process control block */
  struct process* new_pcb = malloc(sizeof(struct process));
  success = pcb_success = new_pcb != NULL;

  /* Initialize process control block */
  if (success) {
    // Ensure that timer_interrupt() -> schedule() -> process_activate()
    // does not try to activate our uninitialized pagedir
    new_pcb->pagedir = NULL;
    t->pcb = new_pcb;

    // Continue initializing the PCB as normal
    t->pcb->main_thread = t;
    strlcpy(t->pcb->process_name, t->name, sizeof t->name);
    // set up parent-child communication
    list_init(&(t->pcb->children_list));
    t->pcb->shared = shared;

    // Initialize the fdt list in the PCB
    // Since the fdt is part of the struct itself, need to use & when passing into funcs
    list_init(&(t->pcb->fdt));

    /* Project 3 - filesys */
    // Support CWD inheritance
    t->pcb->curr_work_dir = NULL;
    // if (fn_->cwd != NULL)
    //   t->pcb->curr_work_dir = dir_reopen(fn_->cwd);
  }

  /* Initialize interrupt frame and load executable. */
  if (success) {
    memset(&if_, 0, sizeof if_);
    if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
    if_.cs = SEL_UCSEG;
    if_.eflags = FLAG_IF | FLAG_MBS;
    /* Start of FPU section */
    // init to previous thread's FPU state (before FPU get loaded with new state)
    char* buff = if_.fpureg;
    asm volatile("fsave (%0)" : : "r"(buff)); // store thread A onto %esp
    asm volatile("fninit; fsave (%0);"
                 :
                 : "r"(if_.fpureg)); // load in (new) thread B's FPU onto struct
    /* End of FPU section */

    success = load(file_name, &if_.eip, &if_.esp);
    asm volatile("frstor (%0)" : : "r"(buff)); // re-store thread A from %esp
  }

  /* Handle failure with succesful PCB malloc. Must free the PCB */
  if (!success && pcb_success) {
    // Avoid race where PCB is freed before t->pcb is set to NULL
    // If this happens, then an unfortuantely timed timer interrupt
    // can try to activate the pagedir, but it is now freed memory
    struct process* pcb_to_free = t->pcb;
    t->pcb = NULL;
    free(pcb_to_free);
  }

  /* Clean up. Exit on failure or jump to userspace */
  palloc_free_page(file_name);
  if (!success) {
    if (shared != NULL) {
      shared->child_pid = -1;
      sema_up(&(shared->exec_sema));
    }
    thread_exit();
  }

  sema_up(&(shared->exec_sema));

  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}

/* Waits for process with PID child_pid to die and returns its exit status.
   If it was terminated by the kernel (i.e. killed due to an
   exception), returns -1.  If child_pid is invalid or if it was not a
   child of the calling process, or if process_wait() has already
   been successfully called for the given PID, returns -1
   immediately, without waiting.

   This function will be implemented in problem 2-2.  For now, it
   does nothing. */
int process_wait(pid_t child_pid) {
  struct thread* t = thread_current();

  struct list_elem* e;
  for (e = list_begin(&(t->pcb->children_list)); e != list_end(&(t->pcb->children_list));
       e = list_next(e)) {
    pc_shared_t* shared = (pc_shared_t*)list_entry(e, pc_shared_t, elem);
    if (shared->child_pid == child_pid) {
      sema_down(&(shared->wait_sema));

      lock_acquire(&(shared->ref_cnt_lock));
      int cnt = shared->ref_cnt -= 1;
      lock_release(&(shared->ref_cnt_lock));
      int exit_code = shared->exit_code;

      if (cnt == 0) {
        list_remove(&(shared->elem));
        free(shared);
      }
      return exit_code;
    }
  }
  return -1;
}

/* Free the current process's resources. */
void process_exit(int exit_code) {
  struct thread* cur = thread_current();
  uint32_t* pd;

  cur->pcb->shared->exit_code = exit_code;

  /* Decrement ref_cnt in the struct we share with our parent, free
     if ref_cnt is now 0 */
  lock_acquire(&(cur->pcb->shared->ref_cnt_lock));
  int cnt = cur->pcb->shared->ref_cnt -= 1;
  lock_release(&(cur->pcb->shared->ref_cnt_lock));

  if (cnt == 0) {
    free(&(cur->pcb->shared));
  }
  /* Decrement ref_cnt in all the structs we share with our children */
  struct list_elem* e;
  struct list_elem* tmp;
  for (e = list_begin(&(cur->pcb->children_list)); e != list_end(&(cur->pcb->children_list));
       e = list_next(e)) {
    pc_shared_t* shared = (pc_shared_t*)list_entry(e, pc_shared_t, elem);
    lock_acquire(&(shared->ref_cnt_lock));
    int cnt = shared->ref_cnt -= 1;
    lock_release(&(shared->ref_cnt_lock));
    if (cnt == 0) {
      tmp = list_remove(&(shared->elem));
      free(shared);
      e = tmp->prev;
    }
  }

  struct list_elem* f; // for file 🙂
  for (f = list_begin(&(cur->pcb->fdt)); f != list_end(&(cur->pcb->fdt)); f = list_next(f)) {
    struct fd* file_d = (struct fd*)list_entry(f, struct fd, elem);
    tmp = list_remove(&(file_d->elem));
    file_close(file_d->file);
    free(file_d);
    f = tmp->prev;
  }

  /* Done all our decrementing and freeing. Unblock parent process. */
  sema_up(&(cur->pcb->shared->wait_sema));

  printf("%s: exit(%d)\n", cur->pcb->process_name, exit_code);

  /* If this thread does not have a PCB, don't worry */
  if (cur->pcb == NULL) {
    thread_exit();
    NOT_REACHED();
  }

  /* Destroy the current process's page directory and switch back
     to the kernel-only page directory. */
  pd = cur->pcb->pagedir;
  if (pd != NULL) {
    /* Correct ordering here is crucial.  We must set
         cur->pcb->pagedir to NULL before switching page directories,
         so that a timer interrupt can't switch back to the
         process page directory.  We must activate the base page
         directory before destroying the process's page
         directory, or our active page directory will be one
         that's been freed (and cleared). */
    cur->pcb->pagedir = NULL;
    pagedir_activate(NULL);
    pagedir_destroy(pd);
  }

  /* Free the PCB of this process and kill this thread
     Avoid race where PCB is freed before t->pcb is set to NULL
     If this happens, then an unfortuantely timed timer interrupt
     can try to activate the pagedir, but it is now freed memory */
  struct process* pcb_to_free = cur->pcb;
  cur->pcb = NULL;
  free(pcb_to_free);

  thread_exit();
}

/* Sets up the CPU for running user code in the current
   thread. This function is called on every context switch. */
void process_activate(void) {
  struct thread* t = thread_current();

  /* Activate thread's page tables. */
  if (t->pcb != NULL && t->pcb->pagedir != NULL)
    pagedir_activate(t->pcb->pagedir);
  else
    pagedir_activate(NULL);

  /* Set thread's kernel stack for use in processing interrupts.
     This does nothing if this is not a user process. */
  tss_update();
}

/* We load ELF binaries.  The following definitions are taken
   from the ELF specification, [ELF1], more-or-less verbatim.  */

/* ELF types.  See [ELF1] 1-2. */
typedef uint32_t Elf32_Word, Elf32_Addr, Elf32_Off;
typedef uint16_t Elf32_Half;

/* For use with ELF types in printf(). */
#define PE32Wx PRIx32 /* Print Elf32_Word in hexadecimal. */
#define PE32Ax PRIx32 /* Print Elf32_Addr in hexadecimal. */
#define PE32Ox PRIx32 /* Print Elf32_Off in hexadecimal. */
#define PE32Hx PRIx16 /* Print Elf32_Half in hexadecimal. */

/* Executable header.  See [ELF1] 1-4 to 1-8.
   This appears at the very beginning of an ELF binary. */
struct Elf32_Ehdr {
  unsigned char e_ident[16];
  Elf32_Half e_type;
  Elf32_Half e_machine;
  Elf32_Word e_version;
  Elf32_Addr e_entry;
  Elf32_Off e_phoff;
  Elf32_Off e_shoff;
  Elf32_Word e_flags;
  Elf32_Half e_ehsize;
  Elf32_Half e_phentsize;
  Elf32_Half e_phnum;
  Elf32_Half e_shentsize;
  Elf32_Half e_shnum;
  Elf32_Half e_shstrndx;
};

/* Program header.  See [ELF1] 2-2 to 2-4.
   There are e_phnum of these, starting at file offset e_phoff
   (see [ELF1] 1-6). */
struct Elf32_Phdr {
  Elf32_Word p_type;
  Elf32_Off p_offset;
  Elf32_Addr p_vaddr;
  Elf32_Addr p_paddr;
  Elf32_Word p_filesz;
  Elf32_Word p_memsz;
  Elf32_Word p_flags;
  Elf32_Word p_align;
};

/* Values for p_type.  See [ELF1] 2-3. */
#define PT_NULL 0           /* Ignore. */
#define PT_LOAD 1           /* Loadable segment. */
#define PT_DYNAMIC 2        /* Dynamic linking info. */
#define PT_INTERP 3         /* Name of dynamic loader. */
#define PT_NOTE 4           /* Auxiliary info. */
#define PT_SHLIB 5          /* Reserved. */
#define PT_PHDR 6           /* Program header table. */
#define PT_STACK 0x6474e551 /* Stack segment. */

/* Flags for p_flags.  See [ELF3] 2-3 and 2-4. */
#define PF_X 1 /* Executable. */
#define PF_W 2 /* Writable. */
#define PF_R 4 /* Readable. */

static bool setup_stack(void** esp, char* argv[MAX_ARGS]);
static bool validate_segment(const struct Elf32_Phdr*, struct file*);
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable);

/* Loads an ELF executable from FILE_NAME into the current thread.
   Stores the executable's entry point into *EIP
   and its initial stack pointer into *ESP.
   Returns true if successful, false otherwise. */
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  // Tokenize file_name and create an array of ptrs

  int j = 0;
  char* val;
  char* executable_name;
  char* rest = file_name;
  char* argv[MAX_ARGS];

  while ((val = strtok_r(rest, " ", &rest))) {
    if (j == 0) {
      executable_name = val;
    }
    argv[j] = val;
    j++;
  }

  argv[j] = NULL;
  file_name = executable_name;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  // Can't edit the executable's file while it's running!
  file_deny_write(file);

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

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
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp, argv))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  if (file != NULL) {
    // Now we can edit it again!
    file_allow_write(file);
  }
  /* We arrive here whether the load is successful or not. */
  file_close(file);
  return success;
}

/* load() helpers. */

static bool install_page(void* upage, void* kpage, bool writable);

/* Checks whether PHDR describes a valid, loadable segment in
   FILE and returns true if so, false otherwise. */
static bool validate_segment(const struct Elf32_Phdr* phdr, struct file* file) {
  /* p_offset and p_vaddr must have the same page offset. */
  if ((phdr->p_offset & PGMASK) != (phdr->p_vaddr & PGMASK))
    return false;

  /* p_offset must point within FILE. */
  if (phdr->p_offset > (Elf32_Off)file_length(file))
    return false;

  /* p_memsz must be at least as big as p_filesz. */
  if (phdr->p_memsz < phdr->p_filesz)
    return false;

  /* The segment must not be empty. */
  if (phdr->p_memsz == 0)
    return false;

  /* The virtual memory region must both start and end within the
     user address space range. */
  if (!is_user_vaddr((void*)phdr->p_vaddr))
    return false;
  if (!is_user_vaddr((void*)(phdr->p_vaddr + phdr->p_memsz)))
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

/* Loads a segment starting at offset OFS in FILE at address
   UPAGE.  In total, READ_BYTES + ZERO_BYTES bytes of virtual
   memory are initialized, as follows:

        - READ_BYTES bytes at UPAGE must be read from FILE
          starting at offset OFS.

        - ZERO_BYTES bytes at UPAGE + READ_BYTES must be zeroed.

   The pages initialized by this function must be writable by the
   user process if WRITABLE is true, read-only otherwise.

   Return true if successful, false if a memory allocation error
   or disk read error occurs. */
static bool load_segment(struct file* file, off_t ofs, uint8_t* upage, uint32_t read_bytes,
                         uint32_t zero_bytes, bool writable) {
  ASSERT((read_bytes + zero_bytes) % PGSIZE == 0);
  ASSERT(pg_ofs(upage) == 0);
  ASSERT(ofs % PGSIZE == 0);

  file_seek(file, ofs);
  while (read_bytes > 0 || zero_bytes > 0) {
    /* Calculate how to fill this page.
         We will read PAGE_READ_BYTES bytes from FILE
         and zero the final PAGE_ZERO_BYTES bytes. */
    size_t page_read_bytes = read_bytes < PGSIZE ? read_bytes : PGSIZE;
    size_t page_zero_bytes = PGSIZE - page_read_bytes;

    /* Get a page of memory. */
    uint8_t* kpage = palloc_get_page(PAL_USER);
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

/* Create a minimal stack by mapping a zeroed page at the top of
   user virtual memory. */
static bool setup_stack(void** esp, char* argv[MAX_ARGS]) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success) {
      *esp = PHYS_BASE;

      // TODO: We should be using memcpy and uint8_t*, not recasting ptrs every time

      int i, l;

      // How many args are there?
      for (l = 0; l < MAX_ARGS; l++) {
        if (argv[l] == NULL) {
          break;
        }
      }

      // Keep an array of the addresses of the args on stack
      // These addresses are going to be the sucessive contents of *esp as we decrement
      // TODO: convert this to uint8_t*
      char* addrs[l];

      // Copy all the actual argv strings, plus a null terminator, onto the stack
      for (i = l - 1; i > -1; i--) {
        size_t len = strlen(argv[i]);
        *esp -= (len + 1);
        addrs[i] = (char*)*esp;
        strlcpy(*esp, argv[i], len + 1);
      }

      // How many more things to put on stack?
      // Align, null, argv ptrs, argc
      size_t ptrs = l + 3;

      // Stack align
      size_t dec_esp = (size_t)*esp - (ptrs * 4);
      size_t align = dec_esp % 16;
      *esp -= align;
      // TODO: Set stack-align section to 0's

      // Put ptrs to argv elements onto the stack
      for (i = l; i > -1; i--) {
        *esp -= 4;
        if (i == l) {
          *((char*)*esp) = (char*)0;
        } else {
          *((int*)*esp) = addrs[i];
        }
      }

      // Add ptr to start of argv onto the stack
      *esp -= 4;
      *((char**)*esp) = *esp + 4;

      // Add argc onto the stack
      *esp -= 4;
      *((int*)*esp) = l;

      // Ptr to fake ret addr
      *esp -= 4;
      *((char*)*esp) = (char*)0;

    } else {
      palloc_free_page(kpage);
    }
  }
  return success;
}

/* Adds a mapping from user virtual address UPAGE to kernel
   virtual address KPAGE to the page table.
   If WRITABLE is true, the user process may modify the page;
   otherwise, it is read-only.
   UPAGE must not already be mapped.
   KPAGE should probably be a page obtained from the user pool
   with palloc_get_page().
   Returns true on success, false if UPAGE is already mapped or
   if memory allocation fails. */
static bool install_page(void* upage, void* kpage, bool writable) {
  struct thread* t = thread_current();

  /* Verify that there's not already a page at that virtual
     address, then map our page there. */
  return (pagedir_get_page(t->pcb->pagedir, upage) == NULL &&
          pagedir_set_page(t->pcb->pagedir, upage, kpage, writable));
}

/* Returns true if t is the main thread of the process p */
bool is_main_thread(struct thread* t, struct process* p) { return p->main_thread == t; }

/* Gets the PID of a process */
pid_t get_pid(struct process* p) { return (pid_t)p->main_thread->tid; }
