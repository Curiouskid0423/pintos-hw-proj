# Answers


1. Address 0xc0000008
As indicated: `Page fault at 0xc0000008: rights violation error reading page in user context.`
2. Instruction address: `eip=0x80488ee`
3. function name <_start>: Instruction that faults `mov 0xc(%ebp),%eax`
4. Function `_start` below
```
void _start(int argc, char* argv[]) { exit(main(argc, argv)); }
```

| Instruction            | Meaning |
| ---------------------- | ------- |
| push  %ebp             | <>      |
| mov   %esp,%ebp        | <>      |
| sub   $0x18,%esp       | <>      |
| mov   0xc(%ebp),%eax   | <>      |
| mov   %eax,0x4(%esp)   | <>      |
| mov   0x8(%ebp),%eax   | <>      |
| mov   %eax,(%esp)      | <>      |
| call  8048094 `<main>` | <>      |
| mov   %eax,(%esp)      | <>      |
| call  804aadb `<exit>` | <>      |

5. It is trying to offset from the stack pointer for some variable, but went too far and thus creats a segment fault.