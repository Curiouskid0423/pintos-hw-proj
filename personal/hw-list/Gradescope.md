1. The output is different every time because each time a function exits, the allocated memory (for stack) are erased, so each time a new process run it has a new stack address.
2. Multiple threads do NOT share the same stack.
3. Multiple threads share the same copy of global variable (can tell from the `common` variabl output).
4. `threadid` is a long / integer id. void* is a void pointer that enables the flexibility of passing in any type.
5. 