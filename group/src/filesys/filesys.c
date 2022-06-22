#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "threads/thread.h"
#include "userprog/process.h"

/* Partition that contains the file system. */
struct block* fs_device;

static void do_format(void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void filesys_init(bool format) {
  fs_device = block_get_role(BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC("No file system device found, can't initialize file system.");

  inode_init();
  free_map_init();

  if (format)
    do_format();

  free_map_open();
  // FIXME: Redirect "." and ".." of root directory to itself
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void filesys_done(void) { free_map_close(); }

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */
bool filesys_create(const char* name, off_t initial_size, bool is_dir) {
  block_sector_t inode_sector = 0;
  size_t L = strlen(name);
  char full_name[L + 1];
  memcpy(full_name, name, sizeof(char) * L);
  full_name[L] = '\0';
  /* Obtain dir and file separately */
  char dir_name[L + 1];
  char file_name[NAME_MAX + 1];
  memset(dir_name, '\0', sizeof(char) * (L + 1));
  memset(file_name, '\0', sizeof(char) * (NAME_MAX + 1));
  bool partition_success = partition_dir_and_file(name, dir_name, file_name);
  if (!partition_success)
    return false;
  /* Obtain struct dir from char* path */
  struct dir* dir = get_dir_from_path(dir_name);
  if (dir == NULL)
    return false;

  /* Free map init */
  bool free_map_success = (dir != NULL && free_map_allocate(1, &inode_sector));
  /* Inode init */
  bool inode_create_success = false;
  if (is_dir)
    inode_create_success = dir_create(inode_sector, initial_size);
  else
    inode_create_success = inode_create(inode_sector, initial_size, false);

  /* dir_add init */
  bool dir_add_success = dir_add(dir, file_name, inode_sector, is_dir);

  bool success = free_map_success && inode_create_success && dir_add_success;

  if (success && is_dir) {
    struct dir* child_dir = get_dir_from_path(full_name);
    init_dir(dir, child_dir);
    dir_close(child_dir);
  }

  if (!success && inode_sector != 0)
    free_map_release(inode_sector, 1);
  dir_close(dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
struct file* filesys_open(const char* name) {

  /* Empty file does not exist */
  if (strcmp(name, "") == 0)
    return NULL;
  /* Obtain dir and file strings separately */
  char dir_name[strlen(name) + 1];
  char file_name[NAME_MAX + 1];
  memset(dir_name, '\0', sizeof(char) * (strlen(name) + 1));
  memset(file_name, '\0', sizeof(char) * (NAME_MAX + 1));
  bool partition_success = partition_dir_and_file(name, dir_name, file_name);
  if (!partition_success)
    return NULL;

  /* Get struct dir* from dir_name string */
  struct dir* dir = get_dir_from_path(dir_name);
  struct inode* inode = NULL;

  /* Acquire inode lock */
  // lock_acquire(&dir->inode->filesys_lock);

  if (dir == NULL) {
    // lock_release(&dir->inode->filesys_lock);
    return NULL;
  }
  if (strlen(file_name) == 0) {
    inode = dir_get_inode(dir);
  } else {
    dir_lookup(dir, file_name, &inode);
    dir_close(dir);
  }
  /* Release inode lock */
  // lock_release(&dir->inode->filesys_lock);

  return file_open(inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */
bool filesys_remove(const char* name) {

  /* Obtain dir and file separately */
  char dir_name[strlen(name) + 1];
  char file_name[NAME_MAX + 1];
  memset(dir_name, '\0', sizeof(char) * (strlen(name) + 1));
  memset(file_name, '\0', sizeof(char) * (NAME_MAX + 1));
  bool partition_success = partition_dir_and_file(name, dir_name, file_name);
  if (!partition_success)
    return false;

  struct dir* dir = get_dir_from_path(dir_name);
  /* Remove `name` from dir's inode entry */
  bool success = dir != NULL && dir_remove(dir, file_name);
  dir_close(dir);

  return success;
}

/* Formats the file system. */
static void do_format(void) {
  printf("Formatting file system...");
  free_map_create();
  if (!dir_create(ROOT_DIR_SECTOR, 16))
    PANIC("root directory creation failed");
  free_map_close();
  printf("done.\n");
}
