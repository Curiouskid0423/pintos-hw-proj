#include "filesys/directory.h"
#include <stdio.h>
#include <string.h>
#include <list.h>
#include "filesys/filesys.h"
#include "filesys/inode.h"
#include "userprog/process.h"
#include "threads/malloc.h"
#include "threads/thread.h"

/* Creates a directory with space for ENTRY_CNT entries in the
   given SECTOR.  Returns true if successful, false on failure. */
bool dir_create(block_sector_t sector, size_t entry_cnt) {
  return inode_create(sector, entry_cnt * sizeof(struct dir_entry), true);
}

/* Opens and returns the directory for the given INODE, of which
   it takes ownership.  Returns a null pointer on failure. */
struct dir* dir_open(struct inode* inode) {
  struct dir* dir = calloc(1, sizeof *dir);
  if (inode != NULL && dir != NULL) {
    dir->inode = inode;
    dir->pos = 0;
    return dir;
  } else {
    inode_close(inode);
    free(dir);
    return NULL;
  }
}

/* Opens the root directory and returns a directory for it.
   Return true if successful, false on failure. */
struct dir* dir_open_root(void) {
  return dir_open(inode_open(ROOT_DIR_SECTOR));
}

/* Opens and returns a new directory for the same inode as DIR.
   Returns a null pointer on failure. */
struct dir* dir_reopen(struct dir* dir) {
  return dir_open(inode_reopen(dir->inode));
}

/* Destroys DIR and frees associated resources. */
void dir_close(struct dir* dir) {
  if (dir != NULL) {
    inode_close(dir->inode);
    free(dir);
  }
}

/* Returns the inode encapsulated by DIR. */
struct inode* dir_get_inode(struct dir* dir) {
  return dir->inode;
}

/* Searches DIR for a file with the given NAME.
   If successful, returns true, sets *EP to the directory entry
   if EP is non-null, and sets *OFSP to the byte offset of the
   directory entry if OFSP is non-null.
   otherwise, returns false and ignores EP and OFSP. */
static bool lookup(const struct dir* dir, const char* name, struct dir_entry* ep, off_t* ofsp) {
  struct dir_entry e;
  size_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (e.in_use && !strcmp(name, e.name)) {
      if (ep != NULL)
        *ep = e;
      if (ofsp != NULL)
        *ofsp = ofs;
      return true;
    }
  return false;
}

/* Searches DIR for a file with the given NAME
   and returns true if one exists, false otherwise.
   On success, sets *INODE to an inode for the file, otherwise to
   a null pointer.  The caller must close *INODE. */
bool dir_lookup(const struct dir* dir, const char* name, struct inode** inode) {
  struct dir_entry e;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  if (dir_get_inode(dir)->sector == ROOT_DIR_SECTOR &&
      (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)) {
    inode = inode_open(ROOT_DIR_SECTOR);
  } else if (lookup(dir, name, &e, NULL)) {
    *inode = inode_open(e.inode_sector);
  } else {
    *inode = NULL;
  }

  return *inode != NULL;
}

/* Adds a file named NAME to DIR, which must not already contain a
   file by that name.  The file's inode is in sector
   INODE_SECTOR.
   Returns true if successful, false on failure.
   Fails if NAME is invalid (i.e. too long) or a disk or memory
   error occurs. */
bool dir_add(struct dir* dir, const char* name, block_sector_t inode_sector, bool is_dir) {
  struct dir_entry e;
  off_t ofs;
  bool success = false;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Check NAME for validity. */
  if (*name == '\0' || strlen(name) > NAME_MAX)
    return false;

  /* Check that NAME is not in use. */
  if (lookup(dir, name, NULL, NULL))
    goto done;

  /* Project 3 - filesys: Do something with isdir */

  /* Acquire inode lock */
  lock_acquire(&dir->inode->filesys_lock);

  /* Set OFS to offset of free slot.
     If there are no free slots, then it will be set to the
     current end-of-file.

     inode_read_at() will only return a short read at end of file.
     Otherwise, we'd need to verify that we didn't get a short
     read due to something intermittent such as low memory. */
  for (ofs = 0; inode_read_at(dir->inode, &e, sizeof e, ofs) == sizeof e; ofs += sizeof e)
    if (!e.in_use)
      break;

  /* Release inode lock */
  lock_release(&dir->inode->filesys_lock);

  /* Write slot. */
  e.in_use = true;
  strlcpy(e.name, name, sizeof e.name);
  e.inode_sector = inode_sector;
  success = inode_write_at(dir->inode, &e, sizeof e, ofs) == sizeof e;

done:
  return success;
}

/* Removes any entry for NAME in DIR.
   Returns true if successful, false on failure,
   which occurs only if there is no file with the given NAME. */
bool dir_remove(struct dir* dir, const char* name) {
  struct dir_entry e;
  struct inode* inode = NULL;
  struct dir* cwd = thread_current()->pcb->curr_work_dir;
  bool success = false;
  off_t ofs;

  ASSERT(dir != NULL);
  ASSERT(name != NULL);

  /* Acquire inode lock */
  lock_acquire(&dir->inode->filesys_lock);

  /* Find directory entry. */
  if (!lookup(dir, name, &e, &ofs))
    goto done;

  /* Open inode. */
  inode = inode_open(e.inode_sector);
  if (inode == NULL)
    goto done;

  // Handle directory removal (allow remove)
  // If a directory is already empty -> goto done
  // If not -> proceed with erasure unless it's "." or ".."
  if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
    goto done;

  struct inode* parent_inode = NULL;
  if (cwd != NULL && get_dir_from_path("..")->inode->sector == inode->sector)
    goto done;

  /* Erase directory entry. */
  e.in_use = false;
  if (inode_write_at(dir->inode, &e, sizeof e, ofs) != sizeof e)
    goto done;

  /* Remove inode. */
  inode_remove(inode);
  success = true;

done:
  /* Release inode lock */
  lock_release(&dir->inode->filesys_lock);
  inode_close(inode);
  return success;
}

/* Reads the next directory entry in DIR and stores the name in
   NAME.  Returns true if successful, false if the directory
   contains no more entries. */
bool dir_readdir(struct dir* dir, char name[NAME_MAX + 1]) {
  struct dir_entry e;
  // FIXME: add filesys_lock

  /* Acquire inode lock before reading dir */
  // lock_acquire(&dir->inode->filesys_lock);
  while (inode_read_at(dir->inode, &e, sizeof e, dir->pos) == sizeof e) {
    dir->pos += sizeof e;
    if (strcmp(e.name, ".") == 0 || strcmp(e.name, "..") == 0) {
      return false;
      // lock_release(&dir->inode->filesys_lock);
    }
    if (e.in_use) {
      strlcpy(name, e.name, NAME_MAX + 1);
      // lock_release(&dir->inode->filesys_lock);
      return true;
    }
  }
  /* Release inode lock after reading dir */
  // lock_release(&dir->inode->filesys_lock);
  return false;
}

/* Extracts a file name part from *SRCP into PART, and updates *SRCP so that the
   next call will return the next file name part. Returns 1 if successful, 0 at
   end of string, -1 for a too-long file name part. */
static int get_next_part(char part[NAME_MAX + 1], const char** srcp) {
  const char* src = *srcp;
  char* dst = part;
  /* Skip leading slashes.  If it's all slashes, we're done. */
  while (*src == '/')
    src++;
  if (*src == '\0')
    return 0;
  /* Copy up to NAME_MAX character from SRC to DST.  Add null terminator. */
  while (*src != '/' && *src != '\0') {
    if (dst < part + NAME_MAX)
      *dst++ = *src;
    else
      return -1;
    src++;
  }
  *dst = '\0';
  /* Advance source pointer. */
  *srcp = src;
  return 1;
}

struct dir* get_dir_from_path(char* path) {
  struct thread* t = thread_current();
  struct dir* cwd;
  char part[NAME_MAX + 1];

  if (path[0] == '/' || t->pcb->curr_work_dir == NULL)
    cwd = dir_open_root();
  else
    cwd = dir_reopen(t->pcb->curr_work_dir);

  while (get_next_part(part, &path) == 1) {
    struct inode* next = NULL;
    /* If the tokenized part does not exist in CWD, return NULL */
    if (!dir_lookup(cwd, part, &next)) {
      dir_close(cwd);
      return NULL;
    } else {
      struct dir* next_dir = dir_open(next);
      if (!next_dir)
        return NULL;
      dir_close(cwd);
      cwd = next_dir;
    }
  }

  if (cwd == NULL || inode_is_removed(cwd->inode))
    return NULL;
  else
    return cwd;
}

bool partition_dir_and_file(const char* name, char* dir, char* file) {

  int path_len = strlen(name);
  char curr_token[NAME_MAX + 1];
  memset(curr_token, '\0', sizeof(char) * (NAME_MAX + 1));
  int step;
  int index = 0;
  if (name[0] == '/')
    dir[index++] = '/';

  while ((step = get_next_part(curr_token, &name)) != 0) {
    if (step == -1)
      return false;
    int L = strlen(curr_token);
    if (index + L >= path_len - 1) {
      break;
    }
    memcpy(&dir[index], curr_token, L * sizeof(char));
    dir[index + L] = '/';
    index += L + 1;
  }
  dir[index] = '\0';
  memcpy(file, curr_token, (strlen(curr_token) + 1) * sizeof(char));
  return true;
}

bool init_dir(struct dir* parent, struct dir* child_dir) {
  block_sector_t parent_inum = inode_to_inumber(dir_get_inode(parent));
  block_sector_t child_inum = inode_to_inumber(dir_get_inode(child_dir));
  if (dir_add(child_dir, ".", child_inum, true) && dir_add(child_dir, "..", parent_inum, true))
    return true;
  else
    return false;
}