---
layout: page
title: Root Check
nav_order: 8
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

Mobile devices can be rooted in order to obtain higher permissions in applications or processes in order to get higher capabilities. Rooting allows: access to process memory of an application for accessing protected data or keys, access to files from applications folders, mounting system partition with *write* permission, creating files in system partition, and so on. Because an application wouldn't like that another could access its files, or to avoid analysis with tools like **frida**, there are techniques for detecting that the phone is rooted and has capabilities to use other analysis tools.


## Techniques

### Check *su* file in **PATH** environment variable paths

The first one checks for the **su** file in all the paths from the environment variable **PATH**:

```java
public static boolean checkRoot1() {
    for (String str : System.getenv("PATH").split(":")) {
        if (new File(str, "su").exists()) {
            return true;
        }
    }
    return false;
}
```

The binary **/system/xbin/which** can be also used to do this check:

```java
public static final boolean hasRootPermission() {
    return ProcUtilsKt.checkCommandExist(new String[]{"/system/xbin/which", "su"});
}
```

### Check Android debug compilation signals

Check of the **Build.TAGS** for value *"test-keys"*:

```java
public static boolean checkRoot2() {
    String str = Build.TAGS;
    return str != null && str.contains("test-keys");
}
```

Or for a value different to *"release-key"*:

```java
public static final boolean checkInvalidBuildTags() {
    String str = Build.TAGS;
    return str == null || (str.equals("release-keys") ^ true);
}
```


### Look for rooting application and artifacts

Finally the checks in Java side include one with hardcoded paths, the checked paths include possible path of **su** binaries, and **root** applications:

The method **exists** from the class **java.io.File** can be used to detect files from *rooting* applications, as well as their artifacts:

```java
public static boolean checkRoot3() {
    for (String str : new String[]{/* Files */}) {
        if (new File(str).exists()) {
            return true;
        }
    }
    return false;
}
```


Check of files using the method **toString** from **java.io.File**:

```java
return new File(/* file path */).toString().equals(/* file path */);
```

Using the method **access** from **android.system.Os**, to check access to a given file:

```java
public static final boolean checkRootCloakFileModifiedOSAccess() {
    if (Build.VERSION.SDK_INT < 21) {
        return false;
    }
    try {
        if (Build.VERSION.SDK_INT >= 21) {
            return Os.access(/* file path */, OsConstants.F_OK);
        }
        return false;
    } catch (Exception unused) {
        return false;
    }
}
```

**Files**

* /system/app/Superuser.apk
* /system/xbin/daemonsu
* /system/etc/init.d/99SuperSUDaemon
* /system/bin/.ext/.su
* /system/etc/.has_su_daemon
* /system/etc/.installed_su_daemon
* /dev/com.koushikdutta.superuser.daemon/
* /system/bin/su
* /sbin/su
* /system/xbin/su
* /system/usr/we-need-root/su-backup
* /system/xbin/mu


In case of *rooting* applications, it's possible to list the installed packages, and check if a known *rooting* application is installed. It is possible to obtain this list using the **Package manager**:

```java
private static final boolean hasMaliciousPackagesInstalled(Context context) {
    String[] strArr = { /* Package name */ };
    List<ApplicationInfo> installedApplications = context.getPackageManager().getInstalledApplications(128);
    List listOf = CollectionsKt.listOf((Object[]) ((String[]) Arrays.copyOf(strArr, strArr.length)));
    for (ApplicationInfo applicationInfo : installedApplications) {
        if (listOf.contains(applicationInfo.packageName)) {
            return true;
        }
    }
    return false;
}
```

**Packages**

* com.noshufou.android.su
* com.thirdparty.superuser
* eu.chainfire.supersu
* com.koushikdutta.superuser
* com.zachspong.temprootremovejb
* com.ramdroid.appquarantine

Another way to check for a **Package** is trying to retrieve information about it with the method **getPackageInfo** from **android.content.pm.PackageManager** class, and then checking the activities from the package, we can find that with **cyanogenmod**, the package **com.android.settings** will contain **cyanogenmod.superuser** as activity:

```java
private static final boolean hasMaliciousActivities(Context context) {
    try {
        PackageManager packageManager = context.getPackageManager();
        HashMap hashMap = new HashMap();
        hashMap.put("com.android.settings", "cyanogenmod.superuser");
        for (Map.Entry entry : hashMap.entrySet()) {
            String str = (String) entry.getValue();
            for (ActivityInfo activityInfo : packageManager.getPackageInfo((String) entry.getKey(), 1).activities) {
                String str2 = activityInfo.name;
                Intrinsics.checkExpressionValueIsNotNull(str2, "act.name");
                if (StringsKt.contains$default((CharSequence) str2, (CharSequence) str, false, 2, (Object) null)) {
                    return true;
                }
            }
        }
    } catch (Exception unused) {
    }
    return false;
}
```

### Look for Magisk in system

Magisk is a known *rooting* software that modifies Android configuration in order to allow applications get higher capabilities. 

```java
public static final Pair<String, String> executeCommand(@NotNull String[] strArr) {
    Intrinsics.checkParameterIsNotNull(strArr, "cmd");
    try {
        Process exec = Runtime.getRuntime().exec(strArr);
        Intrinsics.checkExpressionValueIsNotNull(exec, "process");
        InputStream inputStream = exec.getInputStream();
        Intrinsics.checkExpressionValueIsNotNull(inputStream, "process.inputStream");
        String readOutput = readOutput(inputStream);
        InputStream errorStream = exec.getErrorStream();
        Intrinsics.checkExpressionValueIsNotNull(errorStream, "process.errorStream");
        String readOutput2 = readOutput(errorStream);
        exec.waitFor();
        return new Pair<>(readOutput, readOutput2);
    } catch (IOException | InterruptedException | Exception unused) {
        return new Pair<>(BuildConfig.FLAVOR, BuildConfig.FLAVOR);
    }
}

public static final boolean isMagiskInstalled() {
    StringBuilder sb = new StringBuilder();
    sb.append("/system/bin/netstat -x | grep ");
    sb.append("'@[[:alnum:]]\\{32\\}'");
    return ProcUtilsKt.executeCommandWithTimeOut(new String[]{"sh", "-c", sb.toString()}).getFirst().length() > 0;
}
```


Magisk modifies the **selinux** enforce policies, and some protectors check this in order to detect **Magisk**, one of the codes check when the process was created checking its */proc/<pid>* last modification time, and the last modification time of */sys/fs/selinux/enforce*:

```cpp
uint runtime_detection_RootDetector_b
               (undefined8 param_1,undefined8 param_2,uint param_3)

{
  ulong uVar1;
  uint pid;
  int return_values;
  long i;
  ulong j;
  long in_FS_OFFSET;
  char flag;
  char proc_pid_path [32];
  stat proc_pid_stat;
  stat selinux_enforce_stat;
  long CANARY;
  char aux;
  
  CANARY = *(long *)(in_FS_OFFSET + 0x28);
  if (sys_fs_selinux_enforce_decrypted == '\0') {
    i = 0;
    flag = '\0';
    while( true ) {
      while (flag == '\x01') {
        sys_fs_selinux_enforce_decrypted = '\x01';
        flag = '\x02';
      }
      if (flag != '\0') break;
      s_/sys/fs/selinux/enforce_001150e0[i] = s_/sys/fs/selinux/enforce_001150e0[i] + -0x17;
      i = i + 1;
      flag = i == 0x18;
    }
    if (flag != '\x02') {
      do {
                    /* WARNING: Do nothing block with infinite loop */
      } while( true );
    }
  }
  return_values = stat64(PTR_s_/sys/fs/selinux/enforce_001150d0,&selinux_enforce_stat);
  if (return_values == 0) {
    if (proc_d_decrypted == '\0') {
      aux = '\x01';
      flag = 'T';
      i = 8;
      uVar1 = 0;
      while (j = uVar1, aux == '\x01') {
        aux = s_/proc/%d_00115266[j];
        s_/proc/%d_00115266[j] = aux - flag;
        flag = s_/proc/%d_00115266[j | 1] - (aux - flag);
        s_/proc/%d_00115266[j | 1] = flag;
        i = i + -2;
        aux = i != 0;
        uVar1 = j + 2;
        if (!(bool)aux) {
          s_/proc/%d_00115266[j + 2] = s_/proc/%d_00115266[j + 2] - flag;
          proc_d_decrypted = '\x01';
          aux = '\x02';
        }
      }
      if (aux != '\x02') {
        do {
                    /* WARNING: Do nothing block with infinite loop */
        } while( true );
      }
    }
    pid = getpid();
    return_values = sprintf(proc_pid_path,(char *)0x20,s_/proc/%d_00115266,(ulong)pid);
    if (return_values < 1) {
      proc_pid_path[0] = -0x10;
    }
    return_values = stat64(proc_pid_path,&proc_pid_stat);
    if ((return_values == 0) && (proc_pid_stat.st_ctim.tv_sec != 0)) {
      pid = param_3 ^ 0xf7;
      if (selinux_enforce_stat.st_ctim.tv_sec <= proc_pid_stat.st_ctim.tv_sec + -3) {
        pid = param_3;
      }
      if (selinux_enforce_stat.st_ctim.tv_sec != 0) {
        param_3 = pid;
      }
    }
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == CANARY) {
    return param_3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Another check includes also the path */sys/fs/selinux/enforce*, but instead of checking for */proc/<pid>* it checks for */dev* in order to discover when the last *device* was created and with it, check if the modification time of the **selinux** enforce policy is related to the creationg of that *device*:

```cpp
uint runtime_detection_RootDetector_e
               (undefined8 param_1,undefined8 param_2,uint param_3)

{
  int returned_value;
  long i;
  uint uVar1;
  long in_FS_OFFSET;
  char counter;
  stat.conflict dev_stat;
  stat.conflict selinux_enforce_stat;
  long CANARY;
  
  CANARY = *(long *)(in_FS_OFFSET + 0x28);
  if (sys_fs_selinux_enforce_decrypted == '\0') {
    i = 0;
    counter = '\x01';
    while (counter == '\x01') {
      s_/sys/fs/selinux/enforce_001150e0[i] = s_/sys/fs/selinux/enforce_001150e0[i] + -0x17;
      i = i + 1;
      counter = i != 0x18;
      if (!(bool)counter) {
        sys_fs_selinux_enforce_decrypted = '\x01';
        counter = '\x02';
      }
    }
    if (counter != '\x02') {
      do {
                    /* WARNING: Do nothing block with infinite loop */
      } while( true );
    }
  }
  returned_value = stat64(PTR_s_/sys/fs/selinux/enforce_001150d0,&selinux_enforce_stat);
  if (returned_value == 0) {
    if (/dev_decrypted == '\0') {
      i = 0;
      counter = '\x01';
      while (counter == '\x01') {
        s_/dev_001150f8[i] = s_/dev_001150f8[i] + (-0x5b - (char)i);
        i = i + 1;
        counter = i != 5;
        if (!(bool)counter) {
          /dev_decrypted = '\x01';
          counter = '\x02';
        }
      }
      if (counter != '\x02') {
        do {
                    /* WARNING: Do nothing block with infinite loop */
        } while( true );
      }
    }
    returned_value = stat64(PTR_s_/dev_001150d8,&dev_stat);
    if ((returned_value == 0) && (selinux_enforce_stat.st_mtim.tv_nsec != 0)) {
      uVar1 = param_3 ^ 0xf8;
      if (selinux_enforce_stat.st_mtim.tv_nsec <= dev_stat.st_mtim.tv_nsec + 100) {
        uVar1 = param_3;
      }
      if (dev_stat.st_mtim.tv_nsec != 0) {
        param_3 = uVar1;
      }
    }
  }
  if (*(long *)(in_FS_OFFSET + 0x28) == CANARY) {
    return param_3;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```


### Possible check of Xposed framework

**Xposed framework** modifies the */system/bin/app_process*, creation of a daemon process forking two times and waiting until the parent process is zygote, the daemon process tries reading */system/bin/app_process* and extract the **TracerPID** value from */proc/status*.

```cpp
uint runtime_detection_RootDetector_c
               (undefined8 param_1,undefined8 param_2,uint param_3,ulong i)

{
  long lVar1;
  int linux_pipe;
  pid_t pid;
  pid_t pid2;
  uint systembinappprocess_fd;
  undefined4 current_pid;
  long j;
  long unaff_RBP;
  long in_FS_OFFSET;
  char counter;
  int read_tracer_pid;
  int waitstatus;
  pollfd tracerpid;
  linux_pipe_struct pipefd;
  undefined *zygote_name_ptr;
  
  lVar1 = *(long *)(in_FS_OFFSET + 0x28);
  linux_pipe = pipe(&pipefd);
  if (linux_pipe == 0) {
    pid = fork();
    if (pid == 0) {
                    /* child 1 process
                       close the read part of the pipe. */
      close(pipefd.read_pipe);
      pid2 = fork();
      if (pid2 == 0) {
                    /* child 2 process
                       inheritace only the write part of the pipe
                       as the parent closed the read part before forking */
        if (process_decrypted == '\0') {
          counter = '\0';
          while (counter != '\x03') {
            if (counter == '\x02') {
              process_decrypted = '\x01';
              counter = '\x03';
            }
            else if (counter == '\x01') {
              s_process_0011526f[i] = s_process_0011526f[i] ^ (&DAT_00111b26)[i % 0xd];
              s_process_0011526f[i | 1] = s_process_0011526f[i | 1] ^ (&DAT_00111b26)[(i | 1) % 0xd]
              ;
              i = i + 2;
              unaff_RBP = unaff_RBP + -2;
              counter = (unaff_RBP == 0) + '\x01';
            }
            else {
              counter = '\x01';
              unaff_RBP = 8;
              i = 0;
            }
          }
        }
        zygote_name_ptr = __progname._0_8_;
        *__progname._0_8_ = 'z';
        zygote_name_ptr[1] = 'y';
        zygote_name_ptr[2] = 'g';
        zygote_name_ptr[3] = 'o';
        zygote_name_ptr[4] = 't';
        zygote_name_ptr[5] = 'e';
        zygote_name_ptr[6] = '_';
        zygote_name_ptr[7] = 'r';
        zygote_name_ptr[8] = 'e';
        zygote_name_ptr[9] = 'a';
        zygote_name_ptr[10] = 'c';
        zygote_name_ptr[0xb] = 't';
        zygote_name_ptr[0xc] = 'j';
        zygote_name_ptr[0xd] = 's';
        zygote_name_ptr[0xe] = 0;
        prctl(PR_SET_NAME);
        pid2 = getppid();
        if (pid2 != 1) {
          usleep(50000);
          pid2 = getppid();
          if (pid2 != 1) {
            usleep(50000);
            pid2 = getppid();
            if (pid2 != 1) {
              usleep(50000);
              pid2 = getppid();
              if (pid2 != 1) {
                usleep(50000);
                pid2 = getppid();
                if (pid2 != 1) {
                  usleep(50000);
                  pid2 = getppid();
                  if (pid2 != 1) {
                    usleep(50000);
                    pid2 = getppid();
                    if (pid2 != 1) {
                      usleep(50000);
                      pid2 = getppid();
                      if (pid2 != 1) {
                        usleep(50000);
                        pid2 = getppid();
                        if (pid2 != 1) {
                          usleep(50000);
                          pid2 = getppid();
                          if (pid2 != 1) {
                            usleep(50000);
                            pid2 = getppid();
                            if (pid2 != 1) {
                              usleep(50000);
                              pid2 = getppid();
                              if (pid2 != 1) {
                                usleep(50000);
                                pid2 = getppid();
                                if (pid2 != 1) {
                                  usleep(50000);
                                  pid2 = getppid();
                                  if (pid2 != 1) {
                                    usleep(50000);
                                    pid2 = getppid();
                                    if (pid2 != 1) {
                                      usleep(50000);
                                      pid2 = getppid();
                                      if (pid2 != 1) {
                                        usleep(50000);
                                        pid2 = getppid();
                                        if (pid2 != 1) {
                                          usleep(50000);
                                          pid2 = getppid();
                                          if (pid2 != 1) {
                                            usleep(50000);
                                            pid2 = getppid();
                                            if (pid2 != 1) {
                                              usleep(50000);
                                              pid2 = getppid();
                                              if (pid2 != 1) {
                                                usleep(50000);
                                              }
                                            }
                                          }
                                        }
                                      }
                                    }
                                  }
                                }
                              }
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        if (system_bin_app_process_decrypted == '\0') {
          j = 0;
          counter = '\0';
          while( true ) {
            while (counter == '\x01') {
              system_bin_app_process_decrypted = '\x01';
              counter = '\x02';
            }
            if (counter != '\0') break;
            s_/system/bin/app_process_00115277[j] = s_/system/bin/app_process_00115277[j] + -0x37;
            j = j + 1;
            counter = j == 0x18;
          }
          if (counter != '\x02') {
            do {
                    /* WARNING: Do nothing block with infinite loop */
            } while( true );
          }
        }
                    /* linux daemon checks */
        systembinappprocess_fd = open(s_/system/bin/app_process_00115277,O_RDONLY);
        if (systembinappprocess_fd != 0xffffffff) {
          read(systembinappprocess_fd,&tracerpid,1);
          close(systembinappprocess_fd);
        }
        usleep();
        tracerpid.fd = extract_tracerpid_from_proc_status();
        if (tracerpid.fd < 1) {
          systembinappprocess_fd = open(s_/system/bin/app_process_00115277,O_RDONLY);
          if (systembinappprocess_fd != 0xffffffff) {
            read(systembinappprocess_fd,&tracerpid,1);
            close(systembinappprocess_fd);
          }
          usleep();
          tracerpid.fd = extract_tracerpid_from_proc_status();
          if (tracerpid.fd < 1) {
            systembinappprocess_fd = open(s_/system/bin/app_process_00115277,O_RDONLY);
            if (systembinappprocess_fd != 0xffffffff) {
              read(systembinappprocess_fd,&tracerpid,1);
              close(systembinappprocess_fd);
            }
            usleep();
            tracerpid.fd = extract_tracerpid_from_proc_status();
          }
        }
                    /* end of child process 2 */
        write(pipefd.write_pipe,&tracerpid,4);
      }
      close(pipefd.write_pipe);
      current_pid = getpid();
                    /* end of child process 1 */
      kill(current_pid,SIGKILL);
    }
                    /* first parent process */
    waitpid(pid,&waitstatus,0);
    close(pipefd.write_pipe);
    tracerpid.fd = pipefd.read_pipe;
    tracerpid._4_4_ = 1;
    linux_pipe = poll(&tracerpid,1,4000);
    if (linux_pipe < 1) {
      close(pipefd.read_pipe);
    }
    else {
      read_tracer_pid = -1;
      read(pipefd.read_pipe,&read_tracer_pid,4);
      close(pipefd.read_pipe);
      if (0 < read_tracer_pid) {
        param_3 = param_3 ^ 0xf9;
      }
    }
  }
  if (*(long *)(in_FS_OFFSET + 0x28) != lVar1) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return param_3;
}
```


### Detect **busybox**

**busybox** is a software package that contains various Linux utilities, this is commonly installed when a device is rooted. It is possible to detect **busybox** running it and checking if there's an exception:

```java
public static final boolean hasBusyBoxInstalled() {
    try {
        Runtime.getRuntime().exec((new String[]{"busybox"});
        return true;
    } catch (Exception unused) {
        return false;
    }
}
```

### Detection of incorrect permissions in system files

When a device is rooted the partitions can be remounted with different permissions to the ones they should have (e.g. System with read/write permissions), the **java.io.File** class could be used to check the permissions from the files in the next way:

```java
private static final boolean hasExtendedPermissions() {
    HashMap hashMap = new HashMap();
    hashMap.put(/* path */, /* Permissions.VALUE */);
    for (Map.Entry entry : hashMap.entrySet()) {
        File file = new File('/' + ((String) entry.getKey()));
        switch ((Permissions) entry.getValue()) {
            case READ:
                if (!file.canRead()) {
                    break;
                } else {
                    return true;
                }
            case WRITE:
                if (!file.canWrite()) {
                    break;
                } else {
                    return true;
                }
            case READ_WRITE:
                if (file.canRead() && file.canWrite()) {
                    return true;
                }
                break;
        }
    }
    return false;
}
```

**Possible values from Permission**

* **Permissions.READ_WRITE**
* **Permissions.READ**
* **Permissions.WRITE**


**Files and permission checked**

* /data: read/write permission check
* /: write permission check
* /system: write permission check
* /system/bin: write permission check
* /system/sbin: write permission check
* /system/xbin: write permission check
* /vendor/bin: write permission check
* /sys: write permission check
* /sbin: write permission check
* /etc: write permission check
* /proc: write permission check
* /dev: write permission check



## References

* [Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
* [Android Root Detection Techniques](https://www.netspi.com/blog/technical/mobile-application-penetration-testing/android-root-detection-techniques/)
* [Android Mobile Application, Runtime Mischief](https://www.7elements.co.uk/resources/blog/android-mobile-application-runtime-mischief/)