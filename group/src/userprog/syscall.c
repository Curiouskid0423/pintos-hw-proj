#include "userprog/syscall.h"
#include <stdio.h>
#include <stdlib.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/synch.h"
#include "userprog/process.h"
#include "filesys/file.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "filesys/filesys.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "lib/float.h"
// #include "filesys/inode.c"

static void syscall_handler(struct intr_frame*);
struct fd* get_fd_by_num(int fd_num);

void syscall_init(void) { intr_register_int(0x30, 3, INTR_ON, syscall_handler, "syscall"); }

/* 
1. Checks that the pointer is not null
2. Checks that the pointer is in user memory
3. Checks that it points to mapped memory
4. In case of addresses crossing page boundaries, 
    performs the above 3 checks for addr + 4 as well.
5. Returns true if the memory address is valid.
*/
bool valid_addr(void* addr) {
  if (addr == NULL || (addr + 3) == NULL) {
    return false;
  }
  if (!is_user_vaddr(addr) || !is_user_vaddr(addr + 3)) {
    return false;
  }
  struct thread* t = thread_current();
  if (!pagedir_get_page(t->pcb->pagedir, addr) || !pagedir_get_page(t->pcb->pagedir, addr + 3)) {
    return false;
  }
  return true;
}

/* 
Checks that all the stack arguments for a given syscall are
in kernel space and do not cross page boundaries.

the num_args argument is the number of arguments for the syscall
calling this function. we do (#args + 1) so that we account for
the syscall number and the syscall arguments on the argument stack
*/
bool valid_stack(void* esp, int num_args) {
  int to_last_byte = ((num_args + 1) * 4) - 1;
  if (esp + to_last_byte == NULL) {
    return false;
  }
  if (!is_user_vaddr(esp + to_last_byte)) {
    return false;
  }
  struct thread* t = thread_current();
  if (!pagedir_get_page(t->pcb->pagedir, esp + to_last_byte)) {
    return false;
  }
  return true;
}

static void syscall_handler(struct intr_frame* f UNUSED) {
  uint32_t* args = ((uint32_t*)f->esp);
  if (!valid_addr(args)) {
    process_exit(-1);
  }

  int sys_code = args[0];

  /*
   * The following print statement, if uncommented, will print out the syscall
   * number whenever a process enters a system call. You might find it useful
   * when debugging. It will cause tests to fail, however, so you should not
   * include it in your final submission.
   */

  // printf("System call number: %d\n", args[0]);

  // TODO: Make this into switch cases instead
  if (sys_code == SYS_PRACTICE) {
    /* practice() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }
    f->eax = args[1] + 1;

  } else if (sys_code == SYS_HALT) {
    /* halt() syscall */
    shutdown_power_off();

  } else if (sys_code == SYS_EXIT) {
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }
    f->eax = args[1];
    process_exit(args[1]);

  } else if (sys_code == SYS_EXEC) {
    /* exec() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }
    const char* file_name = args[1];
    if (!valid_addr(file_name)) {
      process_exit(-1);
    }

    pid_t child_pid = process_execute(file_name);
    f->eax = child_pid;

  } else if (sys_code == SYS_WAIT) {
    /* wait() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    int exit_code = process_wait(args[1]);
    f->eax = exit_code;

  } else if (sys_code == SYS_CREATE) {
    /* create() syscall */
    if (!valid_stack(args, 2)) {
      process_exit(-1);
    }

    bool success;
    char* name = (char*)args[1];
    off_t initial_size = (off_t)args[2];

    if (!valid_addr(name)) {
      process_exit(-1);
    }

    /* Project 1: creating plain file (not directory) */
    success = filesys_create(name, initial_size, false);
    f->eax = success;

  } else if (sys_code == SYS_REMOVE) {
    /* remove() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    bool success;
    char* name = (char*)args[1];

    if (!valid_addr(name)) {
      process_exit(-1);
    }

    success = filesys_remove(name);
    f->eax = success;

  } else if (sys_code == SYS_OPEN) {
    /* open() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    char* name = (char*)args[1];
    if (!valid_addr(name)) {
      process_exit(-1);
    }

    // set max as 1 so far to reserve those...
    // do i need to store those in here too?
    int max_num = 1;
    struct list* fdt = &(thread_current()->pcb->fdt);
    uint32_t* pd = thread_current()->pcb->pagedir;
    struct list_elem* e;
    struct file* opened_file;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      struct fd* fd = list_entry(e, struct fd, elem);
      if (fd->num > max_num) {
        max_num = fd->num;
      }
    }

    opened_file = filesys_open(name);

    if (opened_file == NULL) {
      f->eax = -1;
    } else {
      struct fd* new_fd = (struct fd*)malloc(sizeof(struct fd));
      new_fd->num = max_num + 1;
      new_fd->file = opened_file;

      // if this file has the same name as the current executable, deny writes to it
      if (strcmp(name, &(thread_current()->pcb->process_name)) == 0) {
        file_deny_write(new_fd->file);
      }

      list_push_back(fdt, &(new_fd->elem));

      f->eax = new_fd->num;
    }

  } else if (sys_code == SYS_FILESIZE) {
    /* filesize() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    int fd_num = args[1];
    struct list* fdt = &(thread_current()->pcb->fdt);
    struct list_elem* e;
    struct fd* fd;
    struct file* file;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      fd = list_entry(e, struct fd, elem);
      if (fd->num == fd_num) {
        file = fd->file;
      }
    }

    if (file != NULL) {
      f->eax = file_length(file);
    } else {
      f->eax = -1;
      process_exit(-1);
    }

  } else if (sys_code == SYS_READ) {
    if (!valid_stack(args, 3)) {
      process_exit(-1);
    }

    int fd_num = args[1];
    void* buffer = args[2];
    unsigned int size = args[3];

    if (!valid_addr(buffer)) {
      process_exit(-1);
    }

    struct list* fdt = &(thread_current()->pcb->fdt);
    uint32_t* pd = thread_current()->pcb->pagedir;
    struct list_elem* e;
    struct fd* fd;
    struct fd* fd_to_read = NULL;
    struct file* file;

    if (fd_num != NULL) {
      if (fd_num == STDIN_FILENO) {
        char c;
        char* char_buffer = (char*)buffer;
        for (int i = 0; i < size; i++) {
          c = input_getc();
          char_buffer[i] = c;
        }
        f->eax = size;
      } else if (fd_num == STDOUT_FILENO) {
        f->eax = -1;
        process_exit(-1);
      } else {
        for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
          fd = list_entry(e, struct fd, elem);
          if (fd->num == fd_num) {
            fd_to_read = fd;
          }
        }
        if (fd_to_read == NULL) {
          process_exit(-1);
        }
        off_t bytes_read = file_read(fd_to_read->file, buffer, size);
        f->eax = bytes_read;
      }
    } else {
      f->eax = -1;
      process_exit(-1);
    }

  } else if (sys_code == SYS_WRITE) {
    /* write() syscall */
    if (!valid_stack(args, 3)) {
      process_exit(-1);
    }

    // need to understand this
    // check if there's more to do?
    // yes def, rn we only write to stdout, need to write to fd's
    int fd_num = args[1];
    void* buffer = args[2];
    size_t size = args[3];
    if (!valid_addr(buffer)) {
      process_exit(-1);
    }

    if (fd_num == STDOUT_FILENO) {
      if (size > 250) {
        int amnt;
        int total = size;
        int pos = 0;

        while (total != 0) {

          if (total < 250) {
            amnt = total;
          } else {
            amnt = 250;
          }

          putbuf(&(buffer[pos]), amnt);
          total -= amnt;
        }

      } else {
        putbuf(buffer, size);
      }
      f->eax = size;
    } else {

      // first try getting the fd
      struct list* fdt = &(thread_current()->pcb->fdt);
      struct list_elem* e;
      struct fd* fd;
      struct fd* fd_to_read = NULL;

      for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
        fd = list_entry(e, struct fd, elem);
        if (fd->num == fd_num) {
          fd_to_read = fd;
        }
      }

      // if it didn't work, fail
      if (fd_to_read == NULL) {
        process_exit(-1);
      }

      struct inode* curr_inode = file_get_inode(fd_to_read->file);
      if (inode_is_dir(curr_inode))
        process_exit(-1);

      // if it did, call write...
      off_t written = file_write(fd_to_read->file, buffer, size);
      f->eax = written;
    }

  } else if (sys_code == SYS_SEEK) {
    /* seek() syscall */
    if (!valid_stack(args, 2)) {
      process_exit(-1);
    }

    int fd_num = args[1];
    unsigned int position = args[2];

    struct list* fdt = &(thread_current()->pcb->fdt);
    struct list_elem* e;
    struct fd* fd;
    struct fd* fd_to_read;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      fd = list_entry(e, struct fd, elem);
      if (fd->num == fd_num) {
        fd_to_read = fd;
      }
    }

    file_seek(fd_to_read->file, position);

  } else if (sys_code == SYS_TELL) {
    /* tell() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }
    int fd_num = args[1];

    struct list* fdt = &(thread_current()->pcb->fdt);
    struct list_elem* e;
    struct fd* fd;
    struct fd* fd_to_read;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      fd = list_entry(e, struct fd, elem);
      if (fd->num == fd_num) {
        fd_to_read = fd;
      }
    }

    off_t loc = file_tell(fd_to_read->file);

    f->eax = loc;

  } else if (sys_code == SYS_CLOSE) {
    /* close() syscall */
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    int fd_num = args[1];

    // TODO
    // file_close()
    // look very closely at allow and deny write logic here and in file_open()
    // need this to pass rox-* tests
    struct list* fdt = &(thread_current()->pcb->fdt);
    struct list_elem* e;
    struct fd* fd;
    struct fd* fd_to_read = NULL;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      fd = list_entry(e, struct fd, elem);
      if (fd->num == fd_num) {
        fd_to_read = fd;
      }
    }

    if (fd_to_read == NULL) {

      process_exit(-1);
    }

    file_close(fd_to_read->file);
    list_remove(&(fd_to_read->elem));

  } /* For FPU compute e */
  else if (sys_code == SYS_COMPUTE_E) {

    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }
    f->eax = sys_sum_to_e(args[1]);

  } else if (sys_code == SYS_INUMBER) {
    if (!valid_stack(args, 1)) {
      process_exit(-1);
    }

    int fd_num = args[1];

    // first try getting the fd
    struct list* fdt = &(thread_current()->pcb->fdt);
    struct list_elem* e;
    struct fd* fd;
    struct fd* fd_to_read = NULL;

    for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
      fd = list_entry(e, struct fd, elem);
      if (fd->num == fd_num) {
        fd_to_read = fd;
      }
    }

    // if it didn't work, fail
    if (fd_to_read == NULL) {
      process_exit(-1);
    }

    int inumber = inode_get_inumber(fd_to_read->file->inode);

    f->eax = inumber;
  }
  /* Project 3 - filesys */
  else if (sys_code == SYS_MKDIR) {
    if (!valid_stack(args, 1))
      process_exit(-1);

    char* dir_name = (char*)args[1];

    /* Account for "." and "..", but intentially ask
      for init_size > 2 to avoid inode_write_at failure. */

    // FIXME: This is a hack. You should only be asking for init_size = 2
    off_t init_size = 4;
    f->eax = filesys_create(dir_name, init_size, true);

  } else if (sys_code == SYS_ISDIR) {

    if (!valid_stack(args, 1))
      process_exit(-1);

    int fd_num = (int)args[1];
    struct fd* target = get_fd_by_num(fd_num);
    f->eax = inode_is_dir(file_get_inode(target->file));

  } else if (sys_code == SYS_CHDIR) {

    if (!valid_stack(args, 1))
      process_exit(-1);

    char* new_cwd = (char*)args[1];
    struct thread* t = thread_current();

    struct dir* cwd = get_dir_from_path(new_cwd);

    if (cwd != NULL) {
      dir_close(t->pcb->curr_work_dir);
      t->pcb->curr_work_dir = cwd;
      f->eax = true;
    } else
      f->eax = false;

  } else if (sys_code == SYS_READDIR) {

    if (!valid_stack(args, 2))
      process_exit(-1);

    int fd = (int)args[1];
    char* name = (char*)args[2];

    if (fd <= 0 || strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
      f->eax = false;
      return;
    }
    struct inode* inode = get_fd_by_num(fd)->file->inode;
    if (inode == NULL || !inode_is_dir(inode)) {
      f->eax = false;
      return;
    }
    struct dir* dir_to_read = dir_open(inode);

    f->eax = dir_readdir(dir_to_read, name);

  } else if (sys_code == SYS_INUMBER) {

    if (!valid_stack(args, 1))
      process_exit(-1);

    int fd = (int)args[1];
    struct file* file_to_read = get_fd_by_num(fd)->file;
    f->eax = inode_to_inumber(file_get_inode(file_to_read));
  }
}

struct fd* get_fd_by_num(int fd_num) {
  struct list* fdt = &(thread_current()->pcb->fdt);
  struct list_elem* e;
  struct fd* fd;
  for (e = list_begin(fdt); e != list_end(fdt); e = list_next(e)) {
    fd = list_entry(e, struct fd, elem);
    if (fd->num == fd_num) {
      return fd;
    }
  }
  return NULL;
}