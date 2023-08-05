---
layout: default
title: Anti-DBI
nav_order: 2
collection: techniques
---

{: .no_toc }

<details open markdown="block">
  <summary>
    Table of contents
  </summary>
  {: .text-delta }
- TOC
{:toc}
</details>

## Description

Binary instrumentation is an analysis technique where a binary is modified with different techniques in order to instrumentally run it, being able to monitor its execution. Different techniques are proposed for instrumenting a binary and its methods or functions: a *trampoline* can be inserted into the code at the beginning of the function in order to jump to instrumentation code, an import address can be replaced in the *GOT* section of the *ELF* file, even code can be rewritten to modify branching instructions for jumping to instrumentation code. This can be done from a library injected through **ptrace** syscall, or through a library loaded by system with a modified **LD_PRELOAD**. 

Another binary instrumentation technique is using a *tracer*, which copies code to a *shadow* memory owned by the injected library, once the code is copied, instrumentation code can be inserted before and after each instruction allowing a fine granularity instrumentation of the code with the tradeoff of a low performance.

Known DBI frameworks:

* Frida: frida is a really use to use DBI framework which injects an *agent* in the instrumented process, and through a Javascript API allows to modify the implementation of Java methods, and allows to execute code at the beginning and end of native functions.
* Xposed: is an Android modification framework that allows developers and users to customize and modify the behavior of Android apps and the system itself without the need to modify the actual app or system files. It achieves this by hooking into the Android runtime and dynamically altering the execution of code at runtime.

## Techniques

### Detect DBI in memory maps

When a DBI tool is used this is present in memory as commonly a library is injected in process' memory, the protection could open */proc/self/maps* or */proc/\<pid\>/maps* then read line by line looking for part of the name from the DBI frameworks.

```cpp
void detect_frida_and_xposed(void)
{
  FILE *proc_self_maps_fd;
  char *detected_tampering;
  long in_FS_OFFSET;
  pthread_t thread_id;
  char buffer [520];
  
  proc_self_maps_fd = fopen("/proc/self/maps","r");
  if (proc_self_maps_fd == (FILE *)0x0) {
_error_opening_maps:
    detected_tampering = "Error opening /proc/self/maps! Terminating...";
  }
  else {
    do {
      while( true ) {
        detected_tampering = fgets(buffer,0x200,proc_self_maps_fd);
        if (detected_tampering != (char *)0x0) break;
        fclose(proc_self_maps_fd);
        usleep(500);
        proc_self_maps_fd = fopen("/proc/self/maps","r");
        if (proc_self_maps_fd == (FILE *)0x0) goto _error_opening_maps;
      }
      detected_tampering = strstr(buffer,"frida");
      if (detected_tampering != (char *)0x0) break;
      detected_tampering = strstr(buffer,"xposed");
    } while (detected_tampering == (char *)0x0);
    detected_tampering = "Tampering detected! Terminating...";
  }
  __android_log_print(2,"UnCrackable3",detected_tampering);
                    /* raise a SIGABRT and end program... */
  goodbye();
  CANARY = *(long *)(in_FS_OFFSET + 0x28);
  pthread_create(&thread_id,(pthread_attr_t *)0x0,detect_frida_and_xposed,(void *)0x0);
  global_xor_key._0_9_ = SUB169(ZEXT816(0),0);
  global_xor_key._9_7_ = 0;
  _global_checks_applied = _global_checks_applied + 1;
  if (*(long *)(in_FS_OFFSET + 0x28) != CANARY) {                    
    __stack_chk_fail();
  }
  global_xor_key._9_7_ = 0;
  return;
}
```

## Trampoline detection

*Frida* in order to intercept functions it will rewrite the beginning of the function with a jump to its own agent code, in this way, the execution flow will be modified and code from *frida-agent* will be run instead. It is possible to check this dumping the bytes before and after the tracing of it:

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void
dumpprelude(unsigned char *f)
{	int i;
	int c;

	for(i=0; i<32; i++){
		fprintf(stderr, "%02x", *(f+i));
	}
	fprintf(stderr, "\npress enter...\n");
	read(0, &c, 1);
}

int
f(int x)
{
	fprintf(stderr, "f says hi!\n");
	return ++x;
}

int
main(int argc, char *argv[])
{
	int x;

	dumpprelude((unsigned char*)f);
	dumpprelude((unsigned char*)f);
	memcpy((void*)f, "\xf3\x0f\x1e\xfa\x55", 5);
	dumpprelude((unsigned char*)f);
	x = f(13);
	fprintf(stderr, "x is %d\n", x);
	exit(EXIT_SUCCESS);
}
```

As we can see with this code we are also able to restore those bytes (we must disassemble our original function and then apply the restore), let's going to see the execution:

```console
$> ./ex1
# the original bytes from the function
f30f1efa554889e54883ec10897dfc488b05742d00004889c1ba0b000000be01
press enter...

# once the function has been traced with frida
e96d4d00004889e54883ec10897dfc488b05742d00004889c1ba0b000000be01
press enter...

# after restoring the function
f30f1efa554889e54883ec10897dfc488b05742d00004889c1ba0b000000be01
press enter...

f says hi!
x is 14
$>
```

And if we now observe the console with *frida-trace* running we'll see that execution never stops:

```console
$> frida-trace -a ex1\!0x1296 ex1
Instrumenting...                                                        
sub_1296: Auto-generated handler at "/tmp/__handlers__/ex1/sub_1296.js"
Started tracing 1 function. Press Ctrl+C to stop.                       
Process terminated
$>
```

This was because the detour instruction was never run, then *frida* never runs. The author of the technique provides a macro that can be used to call the functions:

```c
#define HIDECALL(RET,FUNC,PRELUDE,...) \
{   int i; \
    int presz = sizeof(PRELUDE); \
    unsigned char aux[presz]; \
    for(i = 0; i < presz; i++) {\
        if(*(((unsigned char*)FUNC)+i) != PRELUDE[i]){\
            break;\
        } \
    } \
    if(i != presz){ \
        for(i = 0; i < presz; i++){ \
            aux[i] = *(((unsigned char*)FUNC)+i); \
            *(((unsigned char*)FUNC)+i) = PRELUDE[i]; \
        } \
        RET = FUNC(__VA_ARGS__); \
        for(i = 0; i < presz; i++){ \
            *(((unsigned char *)FUNC)+i) = aux[i]; \
        } \
    }else{ \
        RET = FUNC(__VA_ARGS__); \
    } \
}
```

*Frida* framework probably could have solved the issue restoring the permissions of the memory page, avoiding the application to write back the correct bytes of the function, in this case, it is still possible to detect *frida* comparing the bytes of those functions with those written by *frida-agent*.


## Permission flag detection

Frida version: **15.1.17**

Derived from previous technique is possible to detect *frida* checking the permissions of the libraries in */proc/\<pid\>/maps* or */proc/self/maps*, if we can parse those files and extract the memory ranges for each library we will be able to obtain the permissions from the memory pages where a function is, for example, if we hook with *frida* the *libc.so* function *open*, and open is in the address **0xf3afd4f0**, we can *grep* this in its *maps* file:

```console
1|generic_x86:/proc/7888 # cat maps | grep libc | grep f3afd                                                                                                               
f3af7000-f3afd000 r-xp 000b2000 fb:02 251                                /apex/com.android.runtime/lib/bionic/libc.so
f3afd000-f3afe000 rwxp 000b8000 fb:02 251                                /apex/com.android.runtime/lib/bionic/libc.so
```

The second line corresponds to the region where the code of the *open* function is, this region is marked as both writable and executable, our program once it parses the */proc/\<pid\>/maps* or */proc/self/maps* file can detect the permissions of the region where the function to call is located, and detect if the *write* flag is set, in that case, the memory permission has been modified and it's possible to raise an alert.

## Detection of Frida Server

With Frida server an analyst can quickly start the analysis of an application, if we run Frida server in a device, we can connect to it with any of the frida tools (*frida-ps*, *frida-trace*, *frida command*), then this binary will attach to a running process or it will start the process, all this in order to inject the *Frida gadget*. Frida server starts a listening socket in order to receive connections, by default the port number is always the same *27042*, if a program tries to connect to this port, and a connection is established, it is possible that Frida server is running in the device. Frida server allows the user to modify the port where it starts running, so this is a technique easy to bypass. Next is the code of a protection that detects Frida with this mechanism:

```c
long DetectFridaServer(JNIEnv *env)
{
  long lVar1;
  int socket;
  long in_FS_OFFSET;
  char local_ip_addr [10];
  sockaddr_in sockaddr;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  sockaddr.sin_zero._4_4_ = 0;
  sockaddr._4_8_ = 0;
                    /* frida port and AF_INET connection */
  sockaddr._0_4_ = 0xa2690002;
  local_ip_addr._0_8_ = L'\x2e373231';
  local_ip_addr._8_2_ = L'1';
  inet_aton(local_ip_addr,&sockaddr.sin_addr);
  socket = ::socket(AF_INET,SOCK_STREAM,0);
  socket = connect(socket,(sockaddr *)&sockaddr,0x10);
  if (*(long *)(in_FS_OFFSET + 0x28) == lVar1) {
    return (ulong)((socket == -1) + 1);
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

## References

* [Bypassing Frida dynamic function call tracing](https://sysfatal.github.io/bypassfrida-en.html)
* [The engineering behind the reverse engineering](https://frida.re/slides/osdc-2015-the-engineering-behind-the-reverse-engineering.pdf)
* [xHook: A library used in some samples to make a DBI crash](https://github.com/iqiyi/xHook)