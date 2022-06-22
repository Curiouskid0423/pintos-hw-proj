#ifndef FILESYS_INODE_H
#define FILESYS_INODE_H

#include <stdbool.h>
#include "filesys/off_t.h"
#include "devices/block.h"
#include "threads/synch.h"

struct bitmap;
/* On-disk inode.
   Must be exactly BLOCK_SECTOR_SIZE bytes long. */
struct inode_disk {
  block_sector_t direct[10];      /* 10 direct ptrs. */
  block_sector_t indirect;        /* 1 indirect ptr */
  block_sector_t doubly_indirect; /* 1 doubly indirect ptr */
  off_t length;                   /* File size in bytes. */
  unsigned magic;                 /* Magic number. */
  /* Project 3 - filesys */
  // uint32_t unused[113]; /* Not used. */
  bool is_dir;
  bool unused_bool[3];
  uint32_t unused[113]; /* Not used. */
};

/* In-memory inode. */
struct inode {
  struct list_elem elem;  /* Element in inode list. */
  block_sector_t sector;  /* Sector number of disk location. */
  int open_cnt;           /* Number of openers. */
  bool removed;           /* True if deleted, false otherwise. */
  int deny_write_cnt;     /* 0: writes ok, >0: deny writes. */
  struct inode_disk data; /* Inode content. */
  /* Project 3 - filesys */
  struct lock filesys_lock;
};

void inode_init(void);
bool inode_create(block_sector_t, off_t, bool);
struct inode* inode_open(block_sector_t);
struct inode* inode_reopen(struct inode*);
block_sector_t inode_get_inumber(const struct inode*);
void inode_close(struct inode*);
void inode_remove(struct inode*);
off_t inode_read_at(struct inode*, void*, off_t size, off_t offset);
off_t inode_write_at(struct inode*, const void*, off_t size, off_t offset);
void inode_deny_write(struct inode*);
void inode_allow_write(struct inode*);
off_t inode_length(const struct inode*);
bool inode_is_dir(struct inode*);
block_sector_t inode_to_inumber(struct inode*);
bool inode_is_removed(struct inode*);

#endif /* filesys/inode.h */