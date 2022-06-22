#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/wait.h>
#include <termios.h>
#include <unistd.h>

#include "tokenizer.h"

/* Convenience macro to silence compiler warnings about unused function parameters. */
#define unused __attribute__((unused))

#define MAX_BUF 512

/* Whether the shell is connected to an actual terminal or not. */
bool shell_is_interactive;

/* File descriptor for the shell input */
int shell_terminal;

/* Terminal mode settings for the shell */
struct termios shell_tmodes;

/* Process group id for the shell */
pid_t shell_pgid;

int cmd_exit(struct tokens* tokens);
int cmd_help(struct tokens* tokens);
int cmd_cd(struct tokens* tokens);
int cmd_pwd(struct tokens* tokens);
int cmd_exec(struct tokens* tokens);

/* Built-in command functions take token array (see parse.h) and return int */
typedef int cmd_fun_t(struct tokens* tokens);

/* Built-in command struct and lookup table */
typedef struct fun_desc {
  cmd_fun_t* fun;
  char* cmd;
  char* doc;
} fun_desc_t;

fun_desc_t cmd_table[] = {
    {cmd_help, "?", "show this help menu"},
    {cmd_exit, "exit", "exit the command shell"},
    {cmd_cd, "cd", "change directory"},
    {cmd_pwd, "pwd", "show current working directory"},
};

/* Prints a helpful description for the given command */
int cmd_help(unused struct tokens* tokens) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    printf("%s - %s\n", cmd_table[i].cmd, cmd_table[i].doc);
  return 1;
}

/* Exits this shell */
int cmd_exit(unused struct tokens* tokens) { exit(0); }

/* Part 2: pwd */
int cmd_pwd(struct tokens* tokens) {
  if (tokens_get_length(tokens) > 1) {
    printf("pwd: too many arguments.\n");
    return -1;
  }
  char path[MAX_BUF];
  getcwd(path, MAX_BUF);
  printf("%s\n", path);
  return 1;
}

/* Part 2: cd */
int cmd_cd(struct tokens* tokens) {

  if (tokens_get_length(tokens) != 2) {
    printf("cd: please provide only 1 argument for the cd command.\n");
    return -1;
  }
  int ret = chdir(tokens_get_token(tokens, 1));
  if (ret != 0) {
    printf("cd: failed since directory not found.\n");
    return -2;
  }
  return 0;
}

int cmd_exec(struct tokens* tokens) {
  int L = tokens_get_length(tokens);
  int num_tokens = L;
  char* path_name = tokens_get_token(tokens, 0);

  /* Preprocess path_name */
  if (access(path_name, X_OK) != 0) {
    char* path_env = getenv("PATH");
    char* option;
    while ((option = strtok_r(path_env, ":", &path_env))) {
      int N = strlen(option) + strlen(path_name) + 1;
      char* actual_path = malloc(sizeof(char) * N);
      strcpy(actual_path, option);
      actual_path[strlen(option)] = '/';
      strcpy(actual_path + strlen(option) + 1, path_name);
      if (access(actual_path, X_OK) == 0) {
        path_name = actual_path;
        break;
      }
    }
  }
  /* End of preprocess path_name */

  char* out_check = malloc(100 * sizeof(char));
  char* in_check = malloc(100 * sizeof(char));
  bool out_init = false;
  bool in_init = false;
  int end_of_argv = num_tokens;
  if (L > 2) {
    if (strcmp(tokens_get_token(tokens, L - 2), ">") == 0) {
      out_check = tokens_get_token(tokens, L - 1);
      out_init = true;
      end_of_argv = L - 2;
    } else if (strcmp(tokens_get_token(tokens, L - 2), "<") == 0) {
      in_check = tokens_get_token(tokens, L - 1);
      in_init = true;
      end_of_argv = L - 2;
    }
  }
  if (L > 4) {
    if (strcmp(tokens_get_token(tokens, L - 4), ">") == 0) {
      out_check = tokens_get_token(tokens, L - 3);
      out_init = true;
      end_of_argv = L - 4;
    } else if (strcmp(tokens_get_token(tokens, L - 4), "<") == 0) {
      in_check = tokens_get_token(tokens, L - 3);
      in_init = true;
      end_of_argv = L - 4;
    }
  }

  char* argv[end_of_argv + 1]; // Has to include file name
  // Malloc for argv
  for (int i = 0; i < end_of_argv; i += 1) {
    argv[i] = malloc(sizeof(char) * 100);
    argv[i] = tokens_get_token(tokens, i);
  }
  argv[end_of_argv] = NULL; // required for execvs
  pid_t pid = fork();
  if (pid == 0) {
    if (out_init)
      freopen(out_check, "w+", stdout);
    if (in_init)
      freopen(in_check, "r+", stdin);
    int ret = execv(path_name, argv);
    return ret;
  } else if (pid > 0) {
    int status;
    wait(&status);
    return status;
  } else {
    /* Only free memory when failed to fork.
     * Processes will free autonmatically otherwise.
     */
    for (int i = 0; i < end_of_argv; i += 1)
      free(argv[i]);
    return 0;
  }
}

/* Looks up the built-in command, if it exists. */
int lookup(char cmd[]) {
  for (unsigned int i = 0; i < sizeof(cmd_table) / sizeof(fun_desc_t); i++)
    if (cmd && (strcmp(cmd_table[i].cmd, cmd) == 0))
      return i;
  return -1;
}

/* Intialization procedures for this shell */
void init_shell() {
  /* Our shell is connected to standard input. */
  shell_terminal = STDIN_FILENO;

  /* Check if we are running interactively */
  shell_is_interactive = isatty(shell_terminal);

  if (shell_is_interactive) {
    /* If the shell is not currently in the foreground, we must pause the shell until it becomes a
     * foreground process. We use SIGTTIN to pause the shell. When the shell gets moved to the
     * foreground, we'll receive a SIGCONT. */
    while (tcgetpgrp(shell_terminal) != (shell_pgid = getpgrp()))
      kill(-shell_pgid, SIGTTIN);

    /* Saves the shell's process id */
    shell_pgid = getpid();

    /* Take control of the terminal */
    tcsetpgrp(shell_terminal, shell_pgid);

    /* Save the current termios to a variable, so it can be restored later. */
    tcgetattr(shell_terminal, &shell_tmodes);
  }
}

int main(unused int argc, unused char* argv[]) {
  init_shell();

  static char line[4096];
  int line_num = 0;

  /* Please only print shell prompts when standard input is not a tty */
  if (shell_is_interactive)
    fprintf(stdout, "%d: ", line_num);

  while (fgets(line, 4096, stdin)) {
    /* Split our line into words. */
    struct tokens* tokens = tokenize(line);

    /* Find which built-in function to run. */
    int fundex = lookup(tokens_get_token(tokens, 0));

    if (fundex >= 0) {
      cmd_table[fundex].fun(tokens);
    } else {
      /* REPLACE this to run commands as programs. */
      int ret = cmd_exec(tokens);
      if (ret < 0) {
        printf("Error when running user provided program.\n");
        return ret;
      }
    }

    if (shell_is_interactive)
      /* Please only print shell prompts when standard input is not a tty */
      fprintf(stdout, "%d: ", ++line_num);

    /* Clean up memory */
    tokens_destroy(tokens);
  }

  return 0;
}
