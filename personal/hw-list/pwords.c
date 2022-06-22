/*
 * Word count application with one thread per input file.
 *
 * You may modify this file in any way you like, and are expected to modify it.
 * Your solution must read each input file from a separate thread. We encourage
 * you to make as few changes as necessary.
 */

/*
 * Copyright © 2021 University of California, Berkeley
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <stddef.h>
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <pthread.h>

#include "word_count.h"
#include "word_helpers.h"

typedef struct args_holder {
  word_count_list_t* word_count;
  FILE* infile;
} args_holder_t;

void* count_words_thread(void* arguments) {
  args_holder_t* args = (args_holder_t*)arguments;
  count_words(args->word_count, args->infile);
  fclose(args->infile);
  // free(args->word_count);
  pthread_exit("NULL");
}

/*
 * main - handle command line, spawning one thread per file.
 */
int main(int argc, char* argv[]) {
  /* Create the empty data structure. */
  word_count_list_t word_counts;
  init_words(&word_counts);
  FILE* infile = NULL;

  if (argc <= 1) {
    /* Process stdin in a single thread. */
    count_words(&word_counts, stdin);
  } else {
    /* TODO */
    if (argc == 2) {
      infile = fopen(argv[argc - 1], "r");
      count_words(&word_counts, infile);
      fclose(infile);
    } else {
      pthread_t threads[argc - 1];
      int ret_val;

      // Create threads
      for (int i = 1; i < argc; i += 1) {
        infile = fopen(argv[i], "r");
        args_holder_t* hold = malloc(sizeof(args_holder_t));
        if (hold == NULL)
          return -1;
        hold->infile = infile;
        hold->word_count = &word_counts;
        ret_val = pthread_create(&threads[i - 1], NULL, count_words_thread, (void*)hold);
        if (ret_val) {
          printf("ERROR from pthread_create(), code %d\n", ret_val);
          exit(-1);
        }
      }
      // Join threads
      for (int i = 1; i < argc; i += 1) {
        ret_val = pthread_join(threads[i - 1], NULL);
        if (ret_val) {
          printf("ERROR from pthread_join(), code %d\n", ret_val);
          exit(-1);
        }
      }
    }
  }

  /* Output final result of all threads' work. */
  wordcount_sort(&word_counts, less_count);
  fprint_words(&word_counts, stdout);
  return 0;
}
