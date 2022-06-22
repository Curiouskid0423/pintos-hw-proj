/*
 * mm_alloc.c
 */

#include "mm_alloc.h"

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdbool.h>

typedef struct heap_node {
  struct heap_node* prev;
  struct heap_node* next;
  bool free;
  size_t size;
  void* memory;
} heap_node_t;

/* Sentinel node in global scope */
heap_node_t* sentinel = NULL;
int init_sentinel() {
  void* prev_break = sbrk(sizeof(heap_node_t));
  if (prev_break == -1)
    return;
  sentinel = (heap_node_t*)prev_break;
  sentinel->prev = NULL;
  sentinel->next = NULL;
  sentinel->free = false; // Set sentinel to always be occupied
  sentinel->size = 0;
  sentinel->memory = NULL;
}

void init_heap_meta(heap_node_t* ptr, heap_node_t* prev, size_t size, void* mem_ptr, bool free_v) {
  ptr->prev = prev;
  ptr->next = NULL;
  ptr->size = size;
  ptr->memory = mem_ptr;
  ptr->free = free_v;
}

/* Split memory in half */
heap_node_t* split_and_set_memory(heap_node_t* curr_ptr, size_t size) {
  // Splitting
  heap_node_t* new_meta = curr_ptr->memory + size;
  void* new_mem = new_meta + sizeof(heap_node_t);
  size_t new_size = curr_ptr->size - sizeof(heap_node_t) - size;
  init_heap_meta(new_meta, curr_ptr, new_size, new_mem, true);
  // memset(new_mem, 0, new_size); // Should be done in freeing
  // Setting
  curr_ptr->free = false;
  curr_ptr->size = size;
  new_meta->next = curr_ptr->next;
  if (curr_ptr->next != NULL)
    curr_ptr->next->prev = new_meta;
  curr_ptr->next = new_meta;

  return curr_ptr->memory;
}

/* Allocate new memory check + metadata */
heap_node_t* alloc_new_mem(heap_node_t* curr_ptr, size_t size) {
  void* meta_start = sbrk(sizeof(heap_node_t));
  void* mem_start = sbrk(size);
  if (meta_start == -1 || mem_start == -1) {
    // Allocation fails
    return NULL;
  } else {
    heap_node_t* new_meta = (heap_node_t*)meta_start;
    init_heap_meta(new_meta, curr_ptr, size, mem_start, false);
    memset(mem_start, 0, size);
    curr_ptr->next = new_meta;
    // printf("malloced new memory: %x\n", mem_start);s
    return mem_start;
  }
}

/* TODO: User malloc function */
/* Given a size find the appropriate block
*  - if cant find (next == NULL), sbrk then use that new one
*  - if find one, check if the remaining space is large enough 
*    (LARGER THAN NOT EQUAL) for metadata
*    - if yes, split it into two
*    - if not, just use without split
*  - zero fill the page (memset) then return the pointer to it.
*/
void* mm_malloc(size_t size) {
  /* Init sentinel if not exist yet */
  if (sentinel == NULL)
    if (init_sentinel() == -1)
      return NULL;
  if (size == 0)
    return NULL;

  /* Find appropriate block */
  heap_node_t* ptr = sentinel;
  while (ptr->next != NULL) {
    heap_node_t* curr = ptr->next;
    if (curr->free && curr->size >= size) {
      // printf("block %x has memory size %d\n", curr->memory, curr->size);
      if (curr->size > size + sizeof(heap_node_t)) {
        return split_and_set_memory(curr, size);
      } else {
        curr->free = false;
        curr->size = size; // FIXME: Fragmentation issue
        return curr->memory;
      }
    }
    ptr = ptr->next;
  }
  /* If cannot find appropriate block */
  return alloc_new_mem(ptr, size);
}

void* mm_realloc(void* ptr, size_t size) {
  //TODO: Implement realloc
  /* 
  - if size < 0: return NULL
  - if ptr == NULL
    - if size == 0: return NULL
    - if size > 0: mm_malloc(n)
  - else
    - if size == 0: mm_free(ptr)
    - if size > curr_size: normal C's realloc process
    - if curr_size > size > 0: truncate the excess memory
  
  if cannot allocate requested memory in any condition, return NULL 
  and do not modify the original chunk
   */
  heap_node_t* curr_meta = ptr - sizeof(heap_node_t);
  if (size < 0)
    return NULL;
  else if (ptr == NULL) {
    if (size == 0)
      return NULL;
    else {
      return mm_malloc(size);
    }
  } else {
    if (size == 0) {
      mm_free(ptr);
      return NULL;
    } else if (size > curr_meta->size) {
      // Copy data
      void* new_mem = mm_malloc(size);
      memcpy(new_mem, ptr, curr_meta->size);
      // Zero out the original page
      mm_free(ptr);
      return new_mem;
    } else {
      // Truncate excess data
      // FIXME: Should we split the block?
      memset(ptr + size, 0, curr_meta->size - size);
      return ptr;
    }
  }
}

/* Helper function to coalesce consecutive free memory */
void coalesce(heap_node_t* ptr) {
  if (ptr == NULL)
    return;
  if (ptr->next != NULL && ptr->next->free) {
    // Coalesce the next
    heap_node_t* to_remove = ptr->next;
    if (ptr->next->next != NULL) {
      ptr->next->next->prev = ptr;
    }
    ptr->size += ptr->next->size + sizeof(heap_node_t);
    ptr->next = ptr->next->next;
    memset(to_remove, 0, sizeof(heap_node_t));
  }
  if (ptr->prev != NULL && ptr->prev->free) {
    // Coalesce the previous
    if (ptr->next != NULL)
      ptr->next->prev = ptr->prev;
    ptr->prev->next = ptr->next;
    ptr->prev->size += ptr->size + sizeof(heap_node_t);
    memset(ptr, 0, sizeof(heap_node_t));
  }
}

void mm_free(void* ptr) {
  // TODO: Implement free
  if (ptr == NULL)
    return;
  else {
    heap_node_t* meta_free = ptr - sizeof(heap_node_t);
    meta_free->free = true;
    memset(ptr, 0, meta_free->size);
    // Check prev and next for coalesce free memory
    coalesce(meta_free);
  }
}
