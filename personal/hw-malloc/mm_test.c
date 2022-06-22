#include <assert.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>

/* Function pointers to hw3 functions */
void* (*mm_malloc)(size_t);
void* (*mm_realloc)(void*, size_t);
void (*mm_free)(void*);

static void* try_dlsym(void* handle, const char* symbol) {
  char* error;
  void* function = dlsym(handle, symbol);
  if ((error = dlerror())) {
    fprintf(stderr, "%s\n", error);
    exit(EXIT_FAILURE);
  }
  return function;
}

static void load_alloc_functions() {
  void* handle = dlopen("hw3lib.so", RTLD_NOW);
  if (!handle) {
    fprintf(stderr, "%s\n", dlerror());
    exit(EXIT_FAILURE);
  }

  mm_malloc = try_dlsym(handle, "mm_malloc");
  mm_realloc = try_dlsym(handle, "mm_realloc");
  mm_free = try_dlsym(handle, "mm_free");
}

int main() {
  load_alloc_functions();

  // int* data = mm_malloc(sizeof(int) * 10);
  // printf("pointer: %x\n", data);
  // assert(data != NULL);
  // data[0] = 0x162;
  // mm_free(data);

  // int* data2 = mm_malloc(sizeof(int) * 10);
  // printf("pointer2: %x\n", data2);
  // mm_free(data2);

  /* Test coalese (seg fault) */
  int* data = mm_malloc(sizeof(int) * 10);
  assert(data != NULL);
  printf("data ptr: %x\n", data);
  data[0] = 0x162;

  int* data2 = mm_malloc(sizeof(int) * 10);
  assert(data2 != NULL);
  printf("data2 ptr: %x\n", data2);
  mm_free(data2);
  mm_free(data);

  int* reuse = mm_malloc(sizeof(int) * 15);
  printf("reuse ptr: %x\n", reuse);
  /* END of Test */
  puts("malloc test successful!");
}
