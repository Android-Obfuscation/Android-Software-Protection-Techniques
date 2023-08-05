---
layout: page
title: Anti-Debugging
nav_order: 3
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

Debugging is a powerful technique used by analysts to analyze application instruction by instruction, this allows to check the values from memory or the CPU registers in each moment as well as modifying them. While debugging is a powerful technique is also slow as commonly the program is run manually stepping through the instructions.
In Android there are two types of debugging, one which allows analyst debugging Java side using the **Java Debug Wire Protocol (JDWP)**, and the other is the debugging in native side implemented using the Linux/Unix-style debugging syscall called **ptrace**.
For debugging an application this must be debuggable, which is an option in its *AndroidManifest.xml* file.

For both debugging mechanisms exists ways to detect and to avoid debugging.

## Techniques

### Check if an application is debuggable

It is possible to check if an application is debuggable checking the flags from the **ApplicationInfo** object, the constant **FLAG_DEBUGGABLE** (0x2) can be checked to see if the application was set as debuggable in its *AndroidManifest.xml*:

```java
public static void checkIsDebuggable(Context context) {
    if (!eventSent) {
        try {
            if ((context.getPackageManager().getApplicationInfo(context.getPackageName(), 0).flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) {
                eventSent = true;
                NativeBridge.sendDevEvent(EventsConstants.APP_DEBUGGABLE, "reason", EventsConstants.DEBUGGBLE);
            }
        } catch (PackageManager.NameNotFoundException e) {
            e.printStackTrace();
        }
    }
}
```

### The TracerPid value

In Linux whenever a process is traced, its value **TracerPid** in the file */proc/<pid>/status* or */proc/self/status* is set to the *PID* of its tracer process. A program can read that value in order to detect if a process is tracing it or not, in case there's no tracer process the **TracerPid** value will be 0.

```console
$ adb shell ps -A | grep com.example.hellojni
u0_a271      11657   573 4302108  50600 ptrace_stop         0 t com.example.hellojni
$ adb shell cat /proc/11657/status | grep -e "^TracerPid:" | sed "s/^TracerPid:\t//"
TracerPid:      11839
$ adb shell ps -A | grep 11839
u0_a271      11839 11837   14024   4548 poll_schedule_timeout 0 S lldb-server
```

(Snippet taken from Owasp-mstg [Android Anti-Reversing Defenses](https://github.com/OWASP/owasp-mstg/blob/master/Document/0x05j-Testing-Resiliency-Against-Reverse-Engineering.md))


### Anti-debugging with ptrace

The Linux/Unix debugging mechanism is through the system call **ptrace**, in Android is possible to use the same mechanism for debugging native libraries but the Linux system allows only one process as tracer, a common mechanism for avoiding an analyst trace a native library is creating a child process with the syscall **fork**, and then make that child process to trace its parent process, finally the child process just need to keep in an infinite loop receiving signals from parent process and calling **ptrace** to continue the execution.

Parent process can monitor in a *thread* the child process to avoid that an analyst just kill child process and replace it as *tracer*:

```cpp
void anti_debugging_mechanism(void)
{
  __pid_t pid;
  uint ppid;
  long ptrace_return;
  long in_FS_OFFSET;
  pthread_t pthread_id_wstatus;
  long CANARY;
  
  CANARY = *(long *)(in_FS_OFFSET + 0x28);
  pid = fork();
  if (pid == 0) {
    ppid = getppid();
    ptrace_return = ptrace(PTRACE_ATTACH,(ulong)ppid,0,0);
    if (ptrace_return == 0) {
      waitpid(ppid,(int *)&pthread_id_wstatus,0);
      ptrace(PTRACE_CONT,(ulong)ppid,0,0);
      pid = waitpid(ppid,(int *)&pthread_id_wstatus,0);
      if (pid != 0) {
        do {
          if (((uint)pthread_id_wstatus & 0x7f) != 0x7f) {
                    /* WARNING: Subroutine does not return */
            _exit(0);
          }
          ptrace(PTRACE_CONT,(ulong)ppid,0,0);
          pid = waitpid(ppid,(int *)&pthread_id_wstatus,0);
        } while (pid != 0);
      }
    }
  }
  else {

    pthread_create(&pthread_id_wstatus,(pthread_attr_t *)0x0,monitor_child_process,(void *)pid);
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == CANARY) {
    return;
  }                    
  __stack_chk_fail();
}
```

It is also possible to make it more complex, different *tasks* can exist in a process, and the debugger can attach to all of them taking the **PID**s of those tasks from the path */proc/\<pid\>/task*, the next code snippet do that, and also the parent process checks that its **TracerPID** value is equals to the child process **PID**:

```cpp
pid = fork();
if (pid < 0) {
    /* Error creating child process */
}
else {
    if (pid == 0) {
        /* Child process */
        attach_to_process_tasks();
    }
    /* parent process */
    sem_wait(global_sem);
    if (child_process != 1) {
        prctl(PR_SET_DUMPABLE,(ulong)child_process,arg3_00,arg4,arg5);
    }
    tracerpid_pid = extract_tracerpid_from_proc_status();
    child_pid = pid;
    if (tracerpid_pid < 0) {
        child_pid = -9;
    }
    else {
        if (tracerpid_pid == child_pid) {
            /* Check correct */
        }
        else {
            /* in case child process is not debugging us
                kill the process */
            kill(pid,SIGKILL);
            child_pid = 10;
        }
    }
}


/* Child process functions */
void attach_to_process_tasks(void)
{
  pid_t parent_pid;
  int are_tasks_ptraced;
  
  parent_pid = getppid();
  are_tasks_ptraced = apply_ptrace_to_all_process_tasks(parent_pid);
  sem_post();
  if ((char)are_tasks_ptraced != '\0') {
                    /* tasks have been correctly ptraced */
    infinite_debugger_tasks();
  }
                    /* WARNING: Subroutine does not return */
  _exit(0);
}

int apply_ptrace_to_all_process_tasks(pid_t pid_to_track)
{
  pid_t pVar1;
  int pid;
  DIR *dirp;
  dirent *file_from_proc_pid_task;
  long return_ptrace;
  uint return_value;
  long *data_buffer;
  long length;
  ulong i;
  long in_FS_OFFSET;
  char flag;
  int wstatus;
  char proc_pid_task [128];
  long CANARY;
  byte hooked_tasks;
  
  CANARY = *(long *)(in_FS_OFFSET + 0x28);

  return_value = 0;
  sprintf(proc_pid_task,(char *)128,s_/proc/%d/task_00115205);
  dirp = opendir(proc_pid_task);
  if (dirp != (DIR *)0x0) {
    file_from_proc_pid_task = readdir(dirp);
    if (file_from_proc_pid_task == (dirent *)0x0) {
      hooked_tasks = 0;
    }
    else {
      hooked_tasks = 0;
      do {
        if (file_from_proc_pid_task->d_name[0] == '.') {
_go_to_next_file:
          file_from_proc_pid_task = readdir(dirp);
        }
        else {
          pid = atoi(file_from_proc_pid_task->d_name);
                    /* attach to specified task */
          return_ptrace = ptrace(PTRACE_ATTACH,pid,(long *)0x0,(long *)0x0);
          if (return_ptrace != 0) goto _go_to_next_file;
          pVar1 = waitpid(pid,&wstatus,0x40000000);
          if (0 < pVar1) {
            if ((wstatus & _WSTATUS) == _WSTOPPED) {
              return_value = (uint)wstatus >> 8 & 0xff;
              data_buffer = (long *)(ulong)return_value;
              if (return_value - 0x13 < 4) {
                data_buffer = (long *)0x0;
              }
                    /* continue the process now that has been attached */
              ptrace(PTRACE_CONT,pid,(long *)0x0,data_buffer);
            }
          }
          file_from_proc_pid_task = readdir(dirp);
          hooked_tasks = 1;
        }
      } while (file_from_proc_pid_task != (dirent *)0x0);
    }
    closedir(dirp);
    return_value = (uint)hooked_tasks;
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == CANARY) {
    return return_value;
  }
  __stack_chk_fail();
}

void infinite_debugger_tasks(void)

{
  pid_t pid;
  uint uVar1;
  uint WSTOPSIG_;
  pid_t event;
  uint wstatus;
  
  do {
    while( true ) {
      pid = waitpid(-1,(int *)&wstatus,__WALL);
      if (pid == -1) break;
      if ((0 < pid) && ((wstatus & _WSTATUS) == _WSTOPPED)) {
        WSTOPSIG_ = wstatus >> 8 & 0xff;
        if (WSTOPSIG_ - 0x13 < 4) {
          WSTOPSIG_ = 0;
        }
        if ((WSTOPSIG_ == 5) &&
           (((uVar1 = (int)wstatus >> 8 ^ 5, uVar1 == 0x100 || (uVar1 == 0x300)) ||
            (WSTOPSIG_ = 0, uVar1 == 0x200)))) {
          WSTOPSIG_ = 0;
          ptrace(PTRACE_GETEVENTMSG,pid,(long *)0x0,(long *)&event);
          ptrace(PTRACE_CONT,event,(long *)0x0,(long *)0x0);
        }
        ptrace(PTRACE_CONT,pid,(long *)0x0,(long *)(long)(int)WSTOPSIG_);
      }
    }
  } while (errno != 3);                    
  _exit(0);
}
```



## References

* [Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)