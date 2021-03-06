#include "filesys/inode.h"
#include <list.h>
#include <debug.h>
#include <round.h>
#include <string.h>
#include "filesys/filesys.h"
#include "filesys/free-map.h"
#include "threads/malloc.h"
#include "threads/synch.h"

/* Identifies an inode. */
#define INODE_MAGIC 0x494e4f44

static size_t DIRECT_PTRS = 10;
static size_t INDIRECT_PTRS = 128;
static size_t DOUBLY_PTRS = 16384;

/* Returns the number of sectors to allocate for an inode SIZE
   bytes long. */
static inline size_t bytes_to_sectors(off_t size) { return DIV_ROUND_UP(size, BLOCK_SECTOR_SIZE); }

/* Returns the block device sector that contains byte offset POS
   within INODE.
   Returns -1 if INODE does not contain data for a byte at offset
   POS. */
static block_sector_t byte_to_sector(const struct inode* inode, off_t pos) {

  ASSERT(inode != NULL);

  block_sector_t sector_num;

  if (pos < inode->data.length) {
    block_sector_t sectors = bytes_to_sectors(pos + 1);
    if (sectors <= DIRECT_PTRS) {
      sector_num = inode->data.direct[sectors - 1];
      return sector_num;
    } else if (sectors <= DIRECT_PTRS + INDIRECT_PTRS) {
      block_sector_t idx = sectors - DIRECT_PTRS;
      block_sector_t* reference_block = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device, inode->data.indirect, reference_block);
      sector_num = reference_block[idx - 1];
      free(reference_block);
      return sector_num;
    } else {
      block_sector_t doubly_indirect_idx = (sectors - DIRECT_PTRS - INDIRECT_PTRS - 1) / 128;
      block_sector_t indirect_idx = (sectors - DIRECT_PTRS - INDIRECT_PTRS - 1) % 128;

      block_sector_t* doubly_indirect_block = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
      block_sector_t* indirect_block = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
      block_read(fs_device, inode->data.doubly_indirect, doubly_indirect_block);
      block_read(fs_device, doubly_indirect_block[doubly_indirect_idx], indirect_block);
      sector_num = indirect_block[indirect_idx];
      free(doubly_indirect_block);
      free(indirect_block);
      return sector_num;
    }
  } else {
    return -1;
  }
}

/* Allocate one new sector to the disk_inode, return success */
static size_t sector_allocate(struct inode_disk* disk_inode, size_t allocated, size_t target) {
  static char zeros[BLOCK_SECTOR_SIZE];

  size_t completed = allocated;
  
  /* Allocate direct ptrs */
  if (allocated < DIRECT_PTRS) {
    for (int i = allocated; i < DIRECT_PTRS; i++) {
      if (completed == target) {
        return completed;
      } else if (free_map_allocate(1, &(disk_inode->direct[i]))) {
        block_write(fs_device, disk_inode->direct[i], zeros);
        completed++;
      } else {
        return completed;
      }
    }
  }

  if (completed == target) {
    return completed;
  }
  /* Allocate indirect ptrs */
  if (allocated < DIRECT_PTRS + INDIRECT_PTRS) {
    /* If indirect ptrs have not been allocated, allocate it */
    if (disk_inode->indirect == 0) {
      if (free_map_allocate(1, &(disk_inode->indirect))) {
        block_write(fs_device, disk_inode->indirect, zeros);
      } else {
        return completed;
      }
    }

    block_sector_t* indirect_sector = (block_sector_t*) malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, disk_inode->indirect, indirect_sector);

    for (int j = completed - DIRECT_PTRS; j < INDIRECT_PTRS; j++) {
      if (completed == target) {
        block_write(fs_device, disk_inode->indirect,
                  indirect_sector); // updating indirect block on disk
        free(indirect_sector);
        return completed;
      } else if (free_map_allocate(1, &(indirect_sector[j]))) {
        block_write(fs_device, indirect_sector[j], zeros);
        completed++;
      } else {
        free(indirect_sector);
        return completed;
      }
    }
    block_write(fs_device, disk_inode->indirect,
                  indirect_sector); // updating indirect block on disk
    free(indirect_sector);
    if (completed == target) {
      return completed;
    }
  }


  /* Allocate doubly indirect ptrs */
  if (disk_inode->doubly_indirect == 0) {
    if (free_map_allocate(1, &disk_inode->doubly_indirect)) {
      block_write(fs_device, disk_inode->doubly_indirect, zeros);
    } else {
      return completed;
    }
  }
  block_sector_t* doubly_indirect_sector = (block_sector_t*) malloc(BLOCK_SECTOR_SIZE);
  block_read(fs_device, disk_inode->doubly_indirect, doubly_indirect_sector);

  block_sector_t* indirect_sector = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
  block_sector_t doubly_idx = (completed - INDIRECT_PTRS - DIRECT_PTRS) / 128;

  for (int k = doubly_idx; k < INDIRECT_PTRS; k++) {
    block_read(fs_device, doubly_indirect_sector[k], indirect_sector);
    for (int l = 0; l < INDIRECT_PTRS; l++ ) {
      if (completed == target) {
        block_write(fs_device, doubly_indirect_sector[k], indirect_sector);
        block_write(fs_device, disk_inode->doubly_indirect, doubly_indirect_sector);
        free(doubly_indirect_sector);
        free(indirect_sector);
        return completed;
      }
      if (indirect_sector[l] == 0) {
        if (free_map_allocate(1, &indirect_sector[l])) {
          block_write(fs_device, indirect_sector[l], zeros);
          completed++;
        } else {
          free(indirect_sector);
          free(doubly_indirect_sector);
          return completed;
        }
      } 
    }
    block_write(fs_device, doubly_indirect_sector[k], indirect_sector);
  }
  block_write(fs_device, disk_inode->doubly_indirect, doubly_indirect_sector);
  free(doubly_indirect_sector);
  free(indirect_sector);
  return completed;
}

/* Deallocate one sector to the disk_inode, return success */
static void sector_deallocate(struct inode_disk* disk_inode, size_t allocated) {
  if (allocated <= DIRECT_PTRS) {
    if (disk_inode->indirect != 0) {
      free_map_release(disk_inode->indirect, 1);
      disk_inode->indirect = 0;
    }
    free_map_release(disk_inode->direct[allocated - 1], 1);
    disk_inode->direct[allocated - 1] = 0;
  } else if (allocated <= DIRECT_PTRS + INDIRECT_PTRS) {
    if (disk_inode->doubly_indirect != 0) {
      free_map_release(disk_inode->doubly_indirect, 1);
      disk_inode->doubly_indirect = 0;
    }
    block_sector_t* indirect_sector = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, disk_inode->indirect, indirect_sector);
    free_map_release(indirect_sector[allocated - DIRECT_PTRS - 1], 1);
    indirect_sector[allocated - DIRECT_PTRS - 1] = 0;
    block_write(fs_device, disk_inode->indirect, indirect_sector);
    free(indirect_sector);
  } else {
    block_sector_t doubly_idx = (allocated - INDIRECT_PTRS - DIRECT_PTRS) / 128;
    block_sector_t indirect_idx = (allocated - INDIRECT_PTRS - DIRECT_PTRS) % 128;

    block_sector_t* doubly_indirect_sector = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, disk_inode->doubly_indirect, doubly_indirect_sector);
    block_sector_t* indirect_sector = (block_sector_t*)malloc(BLOCK_SECTOR_SIZE);
    block_read(fs_device, doubly_indirect_sector[doubly_idx], indirect_sector);
    free_map_release(indirect_sector[indirect_idx], 1);
    indirect_sector[indirect_idx] = 0;
    block_write(fs_device, doubly_indirect_sector[doubly_idx], indirect_sector);
    if (indirect_idx == 0) {
      free_map_release(doubly_indirect_sector[doubly_idx], 1);
      doubly_indirect_sector[doubly_idx] = 0;
    }
    block_write(fs_device, disk_inode->doubly_indirect, doubly_indirect_sector);
    if (doubly_idx == 0) {
      free_map_release(disk_inode->doubly_indirect, 1);
      disk_inode->doubly_indirect = 0;
    }
    free(indirect_sector);
    free(doubly_indirect_sector);
  }
}

static void rollback(struct inode_disk* disk_inode, size_t allocated, size_t target) {
  // sector_deallocate(disk_inode, allocated, target);
  while (allocated > target) {
    sector_deallocate(disk_inode, allocated);
    allocated--;
  }
}

/* List of open inodes, so that opening a single inode twice
   returns the same `struct inode'. */
static struct list open_inodes;

/* Initializes the inode module. */
void inode_init(void) { list_init(&open_inodes); }

/* Initializes an inode with LENGTH bytes of data and
   writes the new inode to sector SECTOR on the file system
   device.
   Returns true if successful.
   Returns false if memory or disk allocation fails. */
bool inode_create(block_sector_t sector, off_t length, bool is_dir) {
  struct inode_disk* disk_inode = NULL;
  bool success = false;

  ASSERT(length >= 0);

  /* If this assertion fails, the inode structure is not exactly
     one sector in size, and you should fix that. */
  ASSERT(sizeof *disk_inode == BLOCK_SECTOR_SIZE);

  disk_inode = calloc(1, sizeof *disk_inode);
  if (disk_inode != NULL) {
    size_t sectors = bytes_to_sectors(length);
    disk_inode->length = length;
    disk_inode->magic = INODE_MAGIC;
    disk_inode->indirect = 0;
    disk_inode->doubly_indirect = 0;
    disk_inode->is_dir = is_dir;

    success = true;
    size_t allocated;
    allocated = sector_allocate(disk_inode, 0, sectors);

    if (allocated != sectors) {
      rollback(disk_inode, allocated, 0);
      success = false;
    } else {
      block_write(fs_device, sector, disk_inode);
    }
  }
  free(disk_inode);
  return success;
}

/* Reads an inode from SECTOR
   and returns a `struct inode' that contains it.
   Returns a null pointer if memory allocation fails. */
struct inode* inode_open(block_sector_t sector) {
  struct list_elem* e;
  struct inode* inode;

  /* Check whether this inode is already open. */
  for (e = list_begin(&open_inodes); e != list_end(&open_inodes); e = list_next(e)) {
    inode = list_entry(e, struct inode, elem);
    if (inode->sector == sector) {
      inode_reopen(inode);
      return inode;
    }
  }

  /* Allocate memory. */
  inode = malloc(sizeof *inode);
  if (inode == NULL)
    return NULL;

  /* Initialize. */
  list_push_front(&open_inodes, &inode->elem);
  inode->sector = sector;
  inode->open_cnt = 1;
  inode->deny_write_cnt = 0;
  inode->removed = false;
  lock_init(&(inode->filesys_lock));
  block_read(fs_device, inode->sector, &inode->data);
  return inode;
}

/* Reopens and returns INODE. */
struct inode* inode_reopen(struct inode* inode) {
  if (inode != NULL)
    inode->open_cnt++;
  return inode;
}

/* Returns INODE's inode number. */
block_sector_t inode_get_inumber(const struct inode* inode) { return inode->sector; }

/* Closes INODE and writes it to disk.
   If this was the last reference to INODE, frees its memory.
   If INODE was also a removed inode, frees its blocks. */
void inode_close(struct inode* inode) {
  /* Ignore null pointer. */
  if (inode == NULL)
    return;

  /* Release resources if this was the last opener. */
  if (--inode->open_cnt == 0) {
    /* Remove from inode list and release lock. */
    list_remove(&inode->elem);

    /* Deallocate blocks if removed. */
    if (inode->removed) {
      free_map_release(inode->sector, 1);
      rollback(&inode->data, bytes_to_sectors(inode->data.length), 0);
      // free_map_release(inode->data.start, bytes_to_sectors(inode->data.length));
    }

    free(inode);
  }
}

/* Marks INODE to be deleted when it is closed by the last caller who
   has it open. */
void inode_remove(struct inode* inode) {
  ASSERT(inode != NULL);
  inode->removed = true;
}

/* Reads SIZE bytes from INODE into BUFFER, starting at position OFFSET.
   Returns the number of bytes actually read, which may be less
   than SIZE if an error occurs or end of file is reached. */
off_t inode_read_at(struct inode* inode, void* buffer_, off_t size, off_t offset) {
  uint8_t* buffer = buffer_;
  off_t bytes_read = 0;
  uint8_t* bounce = NULL;

  /* If read starting offset is past EOF -> returns 0 */
  if (offset >= inode->data.length) {
    return 0;
  }

  while (size > 0) {
    /* Disk sector to read, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);
    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;
    int min_left = inode_left < sector_left ? inode_left : sector_left;

    /* Number of bytes to actually copy out of this sector. */
    int chunk_size = size < min_left ? size : min_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Read full sector directly into caller's buffer. */
      block_read(fs_device, sector_idx, buffer + bytes_read);
    } else {
      /* Read sector into bounce buffer, then partially copy
             into caller's buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }
      block_read(fs_device, sector_idx, bounce);
      memcpy(buffer + bytes_read, bounce + sector_ofs, chunk_size);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_read += chunk_size;
  }
  free(bounce);

  return bytes_read;
}

/* Writes SIZE bytes from BUFFER into INODE, starting at OFFSET.
   Returns the number of bytes actually written, which may be
   less than SIZE if end of file is reached or an error occurs.
   (Normally a write at end of file would extend the inode, but
   growth is not yet implemented.) */
off_t inode_write_at(struct inode* inode, const void* buffer_, off_t size, off_t offset) {
  const uint8_t* buffer = buffer_;
  off_t bytes_written = 0;
  uint8_t* bounce = NULL;

  // lock_acquire(&inode->filesys_lock);
  if (inode->deny_write_cnt)
    return 0;

  size_t curr_sectors = bytes_to_sectors(inode->data.length);
  size_t target = bytes_to_sectors(offset + size);

  if (target > curr_sectors) {
    size_t allocated = sector_allocate(&inode->data, curr_sectors, target);
    if (allocated != target) {
      rollback(&inode->data, allocated, curr_sectors);
      return 0;
    }
    // inode->data.length = offset + size;
  }

  // while (bytes_to_sectors(offset + size) > curr_sectors) {
  //   if (!sector_allocate(&inode->data, curr_sectors)) {
  //     rollback(&inode->data, curr_sectors, bytes_to_sectors(inode->data.length));
  //     return 0;
  //   }
  //   curr_sectors++;
  // }

  inode->data.length = offset + size < inode->data.length ? inode->data.length : offset + size;

  while (size > 0) {
    /* Sector to write, starting byte offset within sector. */
    block_sector_t sector_idx = byte_to_sector(inode, offset);

    int sector_ofs = offset % BLOCK_SECTOR_SIZE;

    /* Bytes left in inode, bytes left in sector, lesser of the two. */
    // off_t inode_left = inode_length(inode) - offset;
    int sector_left = BLOCK_SECTOR_SIZE - sector_ofs;

    /* Number of bytes to actually write into this sector. */
    int chunk_size = size < sector_left ? size : sector_left;
    if (chunk_size <= 0)
      break;

    if (sector_ofs == 0 && chunk_size == BLOCK_SECTOR_SIZE) {
      /* Write full sector directly to disk. */
      block_write(fs_device, sector_idx, buffer + bytes_written);
    } else {
      /* We need a bounce buffer. */
      if (bounce == NULL) {
        bounce = malloc(BLOCK_SECTOR_SIZE);
        if (bounce == NULL)
          break;
      }

      /* If the sector contains data before or after the chunk
             we're writing, then we need to read in the sector
             first.  Otherwise we start with a sector of all zeros. */
      if (sector_ofs > 0 || chunk_size < sector_left)
        block_read(fs_device, sector_idx, bounce);
      else
        memset(bounce, 0, BLOCK_SECTOR_SIZE);
      memcpy(bounce + sector_ofs, buffer + bytes_written, chunk_size);
      block_write(fs_device, sector_idx, bounce);
    }

    /* Advance. */
    size -= chunk_size;
    offset += chunk_size;
    bytes_written += chunk_size;
  }
  block_write(fs_device, inode->sector, &inode->data);

  free(bounce);
  // lock_release(&inode->filesys_lock);
  return bytes_written;
}

/* Disables writes to INODE.
   May be called at most once per inode opener. */
void inode_deny_write(struct inode* inode) {
  inode->deny_write_cnt++;
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
}

/* Re-enables writes to INODE.
   Must be called once by each inode opener who has called
   inode_deny_write() on the inode, before closing the inode. */
void inode_allow_write(struct inode* inode) {
  ASSERT(inode->deny_write_cnt > 0);
  ASSERT(inode->deny_write_cnt <= inode->open_cnt);
  inode->deny_write_cnt--;
}

/* Returns the length, in bytes, of INODE's data. */
off_t inode_length(const struct inode* inode) { return inode->data.length; }

bool inode_is_dir(struct inode* curr) { return curr->data.is_dir; }
block_sector_t inode_to_inumber(struct inode* curr) { return curr->sector; }
bool inode_is_removed(struct inode* curr) { return curr->removed; }