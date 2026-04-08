<NOTICE>
This is an early release of CT-Tracer. I do plan on doing heavy modifications to what you see right now.
  
# CF-Tracer
A control flow analysis tool designed to map the control flow path taken by a program.

## Credits
Major thanks to [Daax](https://github.com/daaximus) for helping me with this project.

## Introduction
[Control flow](https://en.wikipedia.org/wiki/Control_flow) can simply be described as the path that a program takes during execution. Tracing the cpu state during these control flow changes can give very good insight on the functionality of a program. For example in the case of a call instruction, you can determine what arguments are being passed into a function and the return value.

## Breakpoint Theory
Coming up with a stable and versatile mental model for breakpointing is a very important thing to do. I had to restart this project 2 times before coming up with my current strategy for safely handling my breakpoints. First, how are we going to be breakpointing? Well, we can pause execution by throwing an exception, and run logic during that pause in a [vectored exception handler](https://learn.microsoft.com/en-us/windows/win32/debug/vectored-exception-handling).

Any instruction guarenteed to cause an exception will work as a breakpoint. The most basic type would be an int 3. However, most anti-debugger routines will specifically search for 0xCC (int 3). I went with `0F 22` as a faulting instruction because that will always throw a `EXCEPTION_PRIV_INSTRUCTION` from user mode. One thing to keep in mind when you are choosing a faulting instruction is to keep it short. If its too long you will surely come across issues where a breakpoint is conflicting with another breakpoint (depending on how you are restoring execution and restoring breakpoints after use).

[Snippet 1] Before adding breakpoints:
```asm
0:  48 83 ec 28             sub    rsp,0x28
4:  48 89 cb                mov    rbx,rcx
7:  48 c7 c1 01 00 00 00    mov    rcx,0x1
e:  48 c7 c2 02 00 00 00    mov    rdx,0x2
15: ff d3                   call   rbx
17: 48 83 c4 28             add    rsp,0x28
1b: c3                      ret
```

[Snippet 2] After adding breakpoints:
```asm
0:  48 83 ec 28             sub    rsp,0x28
4:  48 89 cb                mov    rbx,rcx
7:  48 c7 c1 01 00 00 00    mov    rcx,0x1
e:  48 c7 c2 02 00 00 00    mov    rdx,0x2
15: 0f 22 48                mov    cr1,rax
18: 83 c4 28                add    esp,0x28
1b: 0f 22 00                mov    cr0,rax ; added an extra 00 for demonstration
```

So, assuming we are breakpointing all control flow changes, both call and ret would be breakpointed. Sometimes the breakpoint won't be as clean and this and will misalign instructions after it to the point that it is unreadable, but in this case the only major change we see is the change from rsp to esp and the line numbers.

When the first `0F 22` is hit in line 15. The vectored exception handler will restore the original bytes, calculate the next instruction, and place a breakpoint there. However, the next instruction is unlikely to be the next contiguous instruction. In this case, we will place our breakpoint at the start of the function that is being called (rbx).

[Snippet 3] After breakpoint exception:
```asm
0:  48 83 ec 28             sub    rsp,0x28
4:  48 89 cb                mov    rbx,rcx
7:  48 c7 c1 01 00 00 00    mov    rcx,0x1
e:  48 c7 c2 02 00 00 00    mov    rdx,0x2
15: ff d3                   call   rbx
17: 48 83 c4 28             add    rsp,0x28
1b: 0f 22 00                mov    cr0,rax ; added an extra 00 for demonstration
```

Next, the vectored exception handler will allow for the logic to continue. Directly hitting a breakpoint in the next instruction. This next instruction will restore the breakpoint at line 15, and then restore its own original bytes.

[Snippet 4] After restore exception (Same as [Snippet 2]):
```asm
0:  48 83 ec 28             sub    rsp,0x28
4:  48 89 cb                mov    rbx,rcx
7:  48 c7 c1 01 00 00 00    mov    rcx,0x1
e:  48 c7 c2 02 00 00 00    mov    rdx,0x2
15: 0f 22 48                mov    cr1,rax
18: 83 c4 28                add    esp,0x28
1b: 0f 22 00                mov    cr0,rax ; added an extra 00 for demonstration
```




// To be continued
