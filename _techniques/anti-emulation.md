---
layout: page
title: Anti-Emulation
nav_order: 5
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

Mobile devices can be emulated with different softwares, there are different emulators in the market public emulators and private ones. Inside these emulators Android system can run and with it the applications. Emulators can be easily rooted and instrumented in order to detect the behavior of an application. Applications may want to avoid this to avoid the automatic analysis, both for legit purposes (DRM, IP, etc), and malicious purposes (avoid malware analysis).

The detection of emulators commonly is targeted for specific emulators and these are based on artifact detection.

## Techniques

### System properties detection

As described in description, the techniques used for detecting emulators are specific for the emulator to detect, **qemu** is a well known emulation software that has also been adapted for emulating Android devices, here we will see each of the techniques used to detect this software.

**System property checks**

Detection of a fake camera, **qemu** creates a system property for cameras, the protection obtain the value from the property and check if is equal to the string *"both"*:


```java
public static final boolean hasFakeCameras() {
    return Intrinsics.areEqual(UtilsKt.getProperty("qemu.sf.fake_camera"), "both");
}
```

Other **qemu** system properties refer to *read-only* properties for *kernel* startup, a protection could also check for the value **ro.kernel.qemu**, with the value *"1"*:

```java
public static final boolean isQEMU() {
    return Intrinsics.areEqual(UtilsKt.getProperty("ro.kernel.qemu"), "1");
}
```

There are many other properties that can be checked by a protector in order to detect an emulated environment, these can be checked using a class for representing the name of the property and the value it should have for detecting the emulator, in this case all the next properties can used to check for **qemu**:

```java
private static final Property[] PROPERTIES = {new Property("init.svc.qemud", null), new Property("init.svc.qemu-props", null), new Property("qemu.hw.mainkeys", null), new Property("qemu.sf.fake_camera", null), new Property("qemu.sf.lcd_density", null), new Property("ro.bootloader", "unknown"), new Property("ro.bootmode", "unknown"), new Property("ro.hardware", "goldfish"), new Property("ro.kernel.android.qemud", null), new Property("ro.kernel.qemu.gles", null), new Property("ro.kernel.qemu", "1"), new Property("ro.product.device", "generic"), new Property("ro.product.model", "sdk"), new Property("ro.product.name", "sdk"), new Property("ro.serialno", null)};

public static class Property {
    public String name;
    public String seek_value;

    public Property(String str, String str2) {
        this.name = str;
        this.seek_value = str2;
    }
}

private String getProp(Context context, String str) {
    try {
        Class<?> loadClass = context.getClassLoader().loadClass("android.os.SystemProperties");
        return (String) loadClass.getMethod("get", String.class).invoke(loadClass, str);
    } catch (Exception e) {
        return null;
    }
}

private boolean checkQEmuProps() {
    Property[] propertyArr;
    int i = 0;
    for (Property property : PROPERTIES) {
        String prop = getProp(mContext, property.name);
        if (property.seek_value == null && prop != null) {
            i++;
        }
        if (property.seek_value != null && prop.contains(property.seek_value)) {
            i++;
        }
    }
    if (i >= 5) {
        return true;
    }
    return false;
}
```

It is possible to use the system properties in order to detect **koplayer** emulator, in this case the code snippet is from a native library, which implies that the detection can be done in native side:

```cpp
bool _Z19has_ko_player_propsv(void)
{
  char *value;
  undefined4 first_check;
  undefined4 p_property;
  undefined4 property_ptr;
  
  first_check = ro.ttvmd.caps.acc_decrypted;
  value = (char *)malloc(100);
  __system_property_get(first_check,value);
  if ((value == (char *)0x0) || (*value == '\0')) {
    free(value);
    property_ptr = ro.ttvmd.caps.bat_decrypted;
    value = (char *)malloc(100);
    __system_property_get(property_ptr,value);
    if ((value == (char *)0x0) || (*value == '\0')) {
      free(value);
      property_ptr = ro.ttvmd.caps.cam_decrypted;
      value = (char *)malloc(100);
      __system_property_get(property_ptr,value);
      if ((value == (char *)0x0) || (*value == '\0')) {
        free(value);
        property_ptr = ro.ttvmd.caps.did_decrypted;
        value = (char *)malloc(100);
        __system_property_get(property_ptr,value);
        if ((value == (char *)0x0) || (*value == '\0')) {
          free(value);
          property_ptr = ro.ttvmd.caps.gps_decrypted;
          value = (char *)malloc(100);
          __system_property_get(property_ptr,value);
          if ((value == (char *)0x0) || (*value == '\0')) {
            free(value);
            property_ptr = ro.ttvmd.caps.rmt_decrypted;
            value = (char *)malloc(100);
            __system_property_get(property_ptr,value);
            if ((value == (char *)0x0) || (*value == '\0')) {
              free(value);
              property_ptr = ro.ttvmd.caps.scr_decrypted;
              value = (char *)malloc(100);
              __system_property_get(property_ptr,value);
              if ((value == (char *)0x0) || (*value == '\0')) {
                free(value);
                property_ptr = ttvmd.gps.latitude_decrypted;
                value = (char *)malloc(100);
                __system_property_get(property_ptr,value);
                if ((value == (char *)0x0) || (*value == '\0')) {
                  free(value);
                  property_ptr = ttvmd.gps.longitude_decrypted;
                  value = (char *)malloc(100);
                  __system_property_get(property_ptr,value);
                  if ((value == (char *)0x0) || (*value == '\0')) {
                    free(value);
                    property_ptr = ttvmd.gps.status_decrypted;
                    value = (char *)malloc(100);
                    __system_property_get(property_ptr,value);
                    if ((value == (char *)0x0) || (*value == '\0')) {
                      free(value);
                      property_ptr = ttvmd.gsm.cid_decrypted;
                      value = (char *)malloc(100);
                      __system_property_get(property_ptr,value);
                      if ((value == (char *)0x0) || (*value == '\0')) {
                        free(value);
                        property_ptr = ttvmd.gsm.lac_decrypted;
                        value = (char *)malloc(100);
                        __system_property_get(property_ptr,value);
                        if ((value == (char *)0x0) || (*value == '\0')) {
                          free(value);
                          property_ptr = ttvmd.gsm.mnc_decrypted;
                          value = (char *)malloc(100);
                          __system_property_get(property_ptr,value);
                          if ((value == (char *)0x0) || (*value == '\0')) {
                            free(value);
                            property_ptr = ttvmd.host.version_decrypted;
                            value = (char *)malloc(100);
                            __system_property_get(property_ptr,value);
                            if ((value == (char *)0x0) || (*value == '\0')) {
                              free(value);
                              p_property = ttvmd.surfaceflinger_inited_decrypted;
                              value = (char *)malloc(100);
                              __system_property_get(p_property,value);
                              if ((value == (char *)0x0) || (*value == '\0')) {
                                free(value);
                                return false;
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
  free(value);
  return true;
}
```

The list of properties checked:

* ro.ttvmd.caps.acc
* ro.ttvmd.caps.bat
* ro.ttvmd.caps.cam
* ro.ttvmd.caps.did
* ro.ttvmd.caps.gps
* ro.ttvmd.caps.rmt
* ro.ttvmd.caps.scr
* ttvmd.gps.latitude
* ttvmd.gps.longitude
* ttvmd.gps.status
* ttvmd.gsm.cid
* ttvmd.gsm.lac
* ttvmd.gsm.mnc
* ttvmd.host.version
* ttvmd.surfaceflinger_inited

**Check of props from Nox emulator**

**Nox** emulator has various props that can be checked in order to detect the emulation environment:

```cpp
bool has_nox_props(void)
{
  undefined4 uVar1;
  char *system_property;
  
  uVar1 = persist.nox.hardware_decrypted;
  system_property = (char *)malloc(100);
  __system_property_get(uVar1,system_property);
  if ((system_property == (char *)0x0) || (*system_property == '\0')) {
    free(system_property);
    uVar1 = persist.nox.board_decrypted;
    system_property = (char *)malloc(100);
    __system_property_get(uVar1,system_property);
    if ((system_property == (char *)0x0) || (*system_property == '\0')) {
      free(system_property);
      return false;
    }
  }
  free(system_property);
  return true;
}
```

Props checked:

* persist.nox.hardware
* persist.nox.board


**Check of props from Genymotion**

It is possible to check two **props** in Android with specific values in order to detect **Genymotion** emulator:

```cpp
int is_genymotion_emulator(void)
{
  char *ro.product;
  char *pcVar1;
  int iVar2;
  
  ro.product = (char *)get_ro_product_manufacturer();
  if (ro.product == (char *)0x0) {
LAB_0001c118:
    free(ro.product);
    ro.product = (char *)get_ro_product_vendor_manufacturer();
    if (ro.product != (char *)0x0) {
      pcVar1 = strstr(ro.product,Genymotion_decrypted);
      if (pcVar1 != (char *)0x0) goto LAB_0001c141;
    }
    free(ro.product);
    iVar2 = 0;
  }
  else {
    pcVar1 = strstr(ro.product,Genymotion_decrypted);
    if (pcVar1 == (char *)0x0) goto LAB_0001c118;
LAB_0001c141:
    free(ro.product);
    iVar2 = CONCAT31((int3)((uint)pcVar1 >> 8),1);
  }
  return iVar2;
}
```

**Props** checked with its values checked:

* **ro.product.manufacturer**: Genymotion
* **ro.product.vendor.manufacturer**: Genymotion


### Detection by check of Build class

The class *android.os.Build* contains various constants that are system values, a Java class can access these values in order to make different checks, and these checks can be used for detecting different emulators:

```java
private boolean checkBasic() {
    boolean z = false;
    boolean z2 = Build.FINGERPRINT.startsWith("generic") || Build.MODEL.contains("google_sdk") || Build.MODEL.toLowerCase().contains("droid4x") || Build.MODEL.contains("Emulator") || Build.MODEL.contains("Android SDK built for x86") || Build.MANUFACTURER.contains("Genymotion") || Build.HARDWARE.equals("goldfish") || Build.HARDWARE.equals("vbox86") || Build.PRODUCT.equals("sdk") || Build.PRODUCT.equals("google_sdk") || Build.PRODUCT.equals("sdk_x86") || Build.PRODUCT.equals("vbox86p") || Build.BOARD.toLowerCase().contains("nox") || Build.BOOTLOADER.toLowerCase().contains("nox") || Build.HARDWARE.toLowerCase().contains("nox") || Build.PRODUCT.toLowerCase().contains("nox") || Build.SERIAL.toLowerCase().contains("nox");
    if (z2) {
        return true;
    }
    if (Build.BRAND.startsWith("generic") && Build.DEVICE.startsWith("generic")) {
        z = true;
    }
    boolean z3 = z | z2;
    if (!z3) {
        return "google_sdk".equals(Build.PRODUCT) | z3;
    }
    return true;
}
```

### Check telephony values

Some system features only exist in real devices, or in case of emulator some telephony values are hardcoded and well known.

Check of the system feature *android.hardware.telephony*, this system feature doesn't have to be present in an emulator as this hardware is used for making use of calling services:

```java
private boolean isSupportTelePhony() {
    return mContext.getPackageManager().hasSystemFeature("android.hardware.telephony");
}
```

Another possibility is checking the phone numbers, emulators use fixed phone numbers by default and in case analyst didn't change them, could be detected easily:

```java
private static final String[] PHONE_NUMBERS = {"15555215554", "15555215556", "15555215558", "15555215560", "15555215562", "15555215564", "15555215566", "15555215568", "15555215570", "15555215572", "15555215574", "15555215576", "15555215578", "15555215580", "15555215582", "15555215584"};

private boolean checkPhoneNumber() {
    String line1Number = ((TelephonyManager) mContext.getSystemService("phone")).getLine1Number();
    for (String str : PHONE_NUMBERS) {
        if (str.equalsIgnoreCase(line1Number)) {
            return true;
        }
    }
    return false;
}
```

From the *TelephonyManager* is possible to obtain a phone device id, in the same way the numbers are fixed and well known, it happens with device ids by default:

```java
private static final String[] DEVICE_IDS = {"000000000000000", "e21833235b6eef10", "012345678912345"};

private boolean checkDeviceId() {
    String deviceId = ((TelephonyManager) mContext.getSystemService("phone")).getDeviceId();
    for (String str : DEVICE_IDS) {
        if (str.equalsIgnoreCase(deviceId)) {
            return true;
        }
    }
    return false;
}
```

The international mobile subscriber identity (IMSI) is a number that uniquely identifies every user of a cellular network. Emulators use a fake one, and that value can also be checked:

```java
private static final String[] IMSI_IDS = {"310260000000000"};

private boolean checkImsi() {
    String subscriberId = ((TelephonyManager) mContext.getSystemService("phone")).getSubscriberId();
    for (String str : IMSI_IDS) {
        if (str.equalsIgnoreCase(subscriberId)) {
            return true;
        }
    }
    return false;
}
```

As emulators do not use telephony, the operator will be a fake one with a fake name, this value is commonly **android**, this can be checked in the next way:

```java
private boolean checkOperatorNameAndroid() {
    return ((TelephonyManager) mContext.getSystemService("phone")).getNetworkOperatorName().equalsIgnoreCase("android");
}
```

### Check of files

Different files can be checked to detect an emulator as they commonly need binaries or configuration files to run, these artifacts in case of knowing where the files are, are also easy to catch.

```java
private static final String[] GENY_FILES = {"/dev/socket/genyd", "/dev/socket/baseband_genyd"};
private static final String[] ANDY_FILES = {"fstab.andy", "ueventd.andy.rc"};
private static final String[] NOX_FILES = {"fstab.nox", "init.nox.rc", "ueventd.nox.rc"};
private static final String[] PIPES = {"/dev/socket/qemud", "/dev/qemu_pipe"};
private static final String[] X86_FILES = {"ueventd.android_x86.rc", "ueventd.android_x86_64.rc", "x86.prop", "ueventd.ttVM_x86.rc", "init.ttVM_x86.rc", "fstab.ttVM_x86", "fstab.vbox86", "init.vbox86.rc", "ueventd.vbox86.rc"};

public boolean checkEmulatorFiles() {
    return checkFiles(GENY_FILES, "Geny") || checkFiles(ANDY_FILES, "Andy") || checkFiles(NOX_FILES, "Nox") || checkFiles(PIPES, "Pipes") || checkFiles(X86_FILES, "X86");
}

private boolean checkFiles(String[] strArr, String str) {
    for (String str2 : strArr) {
        if (new File(str2).exists()) {
            return true;
        }
    }
    return false;
}
```

**Check qemu drivers**

It is possible to detect **qemu** checking for possible drivers in */proc/tty/drivers* or */proc/cpuinfo*:

```java
private static final String[] QEMU_DRIVERS = {"goldfish"};

private boolean checkQEmuDrivers() {
    File[] fileArr;
    for (File file : new File[]{new File("/proc/tty/drivers"), new File("/proc/cpuinfo")}) {
        if (file.exists() && file.canRead()) {
            byte[] bArr = new byte[1024];
            try {
                FileInputStream fileInputStream = new FileInputStream(file);
                fileInputStream.read(bArr);
                fileInputStream.close();
            } catch (Exception e) {
                e.printStackTrace();
            }
            String str = new String(bArr);
            for (String str2 : QEMU_DRIVERS) {
                if (str.contains(str2)) {
                    return true;
                }
            }
            continue;
        }
    }
    return false;
}
```


**Check of configuration files**

Configuration files can be different for an emulator than for a real device, for example a startup configuration file would start a service or would create a device for the emulator if needed.

The next snippet checks in **ueventd.rc** for a device from **virtualbox** virtualization software:

```java
private boolean checkUeventdValues() {
    try {
        File file = new File("/ueventd.rc");
        if (file.exists()) {
            BufferedReader bufferedReader = new BufferedReader(new InputStreamReader(new FileInputStream(file)));
            for (String readLine = bufferedReader.readLine(); readLine != null; readLine = bufferedReader.readLine()) {
                if (readLine.startsWith("/dev/vboxuser")) {
                    return true;
                }
            }
        }
    } catch (Exception e) {
    }
    return false;
}
```

It is possible for the emulated environment and the guest environment to share a path where the analyst can push files that the emulated phone can read, or the phone can write files that analyst could read from if the path is shared between host and guest, in case of **BlueStacks** emulator, it is possible to detect it in the next way:

```java
private boolean checkBstSharedFolder() {
    return new File("/sdcard/windows/BstSharedFolder").exists();
}
```

**Check for MEmu App Player files**

There are two possible files that can be present in **MEmu App Player** emulator, these are two *kernel objects* in */system/lib*, the *API* call **access** can be used to check for the files:

```cpp
bool has_memu_files(void)
{
  int iVar1;
  bool bVar2;
  
  iVar1 = access(/system/lib/mg.ko_decrypted,0);
  bVar2 = true;
  if (iVar1 == -1) {
    iVar1 = access(/system/lib/msf.ko_decrypted,0);
    bVar2 = iVar1 != -1;
  }
  return bVar2;
}
```

The accessed files are:

* /system/lib/mg.ko
* /system/lib/msf.ko

**Check for Nox files**

Checks of files for detecting **Nox** emulator, in this case is done through running the command line *ls /system/bin*:

```cpp
char ** get_system_bin_files(void)
{
  char **bin_files;
  
  bin_files = (char **)exec_command_lines(ls_/system/bin_decrypted);
  return bin_files;
}

int has_nox_files_system_bin(void)
{
  bool bVar1;
  bool bVar2;
  undefined4 uVar3;
  char **system_bin_files;
  int iVar4;
  undefined4 result;
  char **p_system_bin_files;
  char *file_to_ceck;
  char *system_bin_file;
  
  system_bin_files = get_system_bin_files();
  file_to_ceck = nox-prop_decrypted;
  if ((system_bin_files != (char **)0x0) &&
     (system_bin_file = *system_bin_files, system_bin_file != (char *)0x0)) {
    p_system_bin_files = system_bin_files;
    bVar2 = false;
    do {
      p_system_bin_files = p_system_bin_files + 1;
      iVar4 = strcmp(file_to_ceck,system_bin_file);
      bVar1 = true;
      if (iVar4 != 0) {
        bVar1 = bVar2;
      }
      free(system_bin_file);
      system_bin_file = *p_system_bin_files;
      bVar2 = bVar1;
    } while (system_bin_file != (char *)0x0);
    free(system_bin_files);
    if (bVar1) {
      return 1;
    }
  }
  system_bin_files = get_system_bin_files();
  file_to_ceck = nox-vbox-sf_decrypted;
  if ((system_bin_files != (char **)0x0) &&
     (system_bin_file = *system_bin_files, system_bin_file != (char *)0x0)) {
    p_system_bin_files = system_bin_files;
    bVar2 = false;
    do {
      p_system_bin_files = p_system_bin_files + 1;
      iVar4 = strcmp(file_to_ceck,system_bin_file);
      bVar1 = true;
      if (iVar4 != 0) {
        bVar1 = bVar2;
      }
      free(system_bin_file);
      system_bin_file = *p_system_bin_files;
      bVar2 = bVar1;
    } while (system_bin_file != (char *)0x0);
    free(system_bin_files);
    if (bVar1) {
      return 1;
    }
  }
  system_bin_files = get_system_bin_files();
  file_to_ceck = noxd_decrypted;
  if ((system_bin_files == (char **)0x0) ||
     (system_bin_file = *system_bin_files, system_bin_file == (char *)0x0)) {
    result = 0;
  }
  else {
    result = 0;
    p_system_bin_files = system_bin_files;
    do {
      p_system_bin_files = p_system_bin_files + 1;
      iVar4 = strcmp(file_to_ceck,system_bin_file);
      uVar3 = 1;
      if (iVar4 != 0) {
        uVar3 = result;
      }
      result = uVar3;
      free(system_bin_file);
      system_bin_file = *p_system_bin_files;
    } while (system_bin_file != (char *)0x0);
    free(system_bin_files);
  }
  return result;
}
```

Checked files:

* nox-prop
* nox-vbox-sf
* noxd

For detecting the files it is also possible to use the API call **pathconf** with the value *0xb* as parameter, in case the return value is *0x1000* it means the artifact exists:

```cpp
int detect_nox_system(void)
{
  ulong uVar1;
  int return_value;
  long i;
  char cVar2;
  ulong k;
  char flag;
  
  if (/system/bin/nox-prop_decrypted == '\0') {
    i = 0;
    flag = '\0';
    while( true ) {
      while (flag == '\x01') {
        /system/bin/nox-prop_decrypted = '\x01';
        flag = '\x02';
      }
      if (flag != '\0') break;
      s_/system/bin/nox-prop_0011528f[i] = s_/system/bin/nox-prop_0011528f[i] + -0x2f;
      i = i + 1;
      flag = i == 0x15;
    }
    if (flag != '\x02') {
      do {
                    /* WARNING: Do nothing block with infinite loop */
      } while( true );
    }
  }
  i = pathconf(s_/system/bin/nox-prop_0011528f,0xb);
  return_value = SYSTEM_BIN_NOX;
  if (i != 0x1000) {
    if (/system/bin/noxd_decrypted == '\0') {
      i = 0;
      flag = '\0';
      while( true ) {
        while (flag == '\x01') {
          /system/bin/noxd_decrypted = '\x01';
          flag = '\x02';
        }
        if (flag != '\0') break;
        s_/system/bin/noxd_001152a4[i] = s_/system/bin/noxd_001152a4[i] + -0xd;
        i = i + 1;
        flag = i == 0x11;
      }
      if (flag != '\x02') {
        do {
                    /* WARNING: Do nothing block with infinite loop */
        } while( true );
      }
    }
    i = pathconf(s_/system/bin/noxd_001152a4,0xb);
    return_value = SYSTEM_BIN_NOXD;
    if (i != 0x1000) {
      if (/system/bin/nox-vbox-sf_decrypted == '\0') {
        i = 0;
        flag = '\0';
        while( true ) {
          while (flag == '\x01') {
            /system/bin/nox-vbox-sf_decrypted = '\x01';
            flag = '\x02';
          }
          if (flag != '\0') break;
          s_/system/bin/nox-vbox-sf_001152b5[i] = s_/system/bin/nox-vbox-sf_001152b5[i] + -0x37;
          i = i + 1;
          flag = i == 0x18;
        }
        if (flag != '\x02') {
          do {
                    /* WARNING: Do nothing block with infinite loop */
          } while( true );
        }
      }
      i = pathconf(s_/system/bin/nox-vbox-sf_001152b5,0xb);
      return_value = SYSTEM_BIN_NOX_VBOX_SF;
      if (i != 0x1000) {
        if (/system/bin/noxspeedup_decrypted == '\0') {
          s_/system/bin/noxspeedup_001152d0[0] = s_/system/bin/noxspeedup_001152d0[0] + -0x4e;
          s_/system/bin/noxspeedup_001152d0[1] = s_/system/bin/noxspeedup_001152d0[1] + -0x4f;
          s_/system/bin/noxspeedup_001152d0[2] = s_/system/bin/noxspeedup_001152d0[2] + -0x50;
          s_/system/bin/noxspeedup_001152d0[3] = s_/system/bin/noxspeedup_001152d0[3] + -0x51;
          s_/system/bin/noxspeedup_001152d0[4] = s_/system/bin/noxspeedup_001152d0[4] + -0x52;
          s_/system/bin/noxspeedup_001152d0[5] = s_/system/bin/noxspeedup_001152d0[5] + -0x53;
          s_/system/bin/noxspeedup_001152d0[6] = s_/system/bin/noxspeedup_001152d0[6] + -0x54;
          s_/system/bin/noxspeedup_001152d0[7] = s_/system/bin/noxspeedup_001152d0[7] + -0x55;
          s_/system/bin/noxspeedup_001152d0[8] = s_/system/bin/noxspeedup_001152d0[8] + -0x56;
          s_/system/bin/noxspeedup_001152d0[9] = s_/system/bin/noxspeedup_001152d0[9] + -0x57;
          s_/system/bin/noxspeedup_001152d0[10] = s_/system/bin/noxspeedup_001152d0[10] + -0x58;
          s_/system/bin/noxspeedup_001152d0[11] = s_/system/bin/noxspeedup_001152d0[11] + -0x59;
          s_/system/bin/noxspeedup_001152d0[12] = s_/system/bin/noxspeedup_001152d0[12] + -0x5a;
          s_/system/bin/noxspeedup_001152d0[13] = s_/system/bin/noxspeedup_001152d0[13] + -0x5b;
          s_/system/bin/noxspeedup_001152d0[14] = s_/system/bin/noxspeedup_001152d0[14] + -0x5c;
          s_/system/bin/noxspeedup_001152d0[15] = s_/system/bin/noxspeedup_001152d0[15] + -0x5d;
          flag = '\0';
          i = 0x10;
          while( true ) {
            while (flag == '\x01') {
              /system/bin/noxspeedup_decrypted = '\x01';
              flag = '\x02';
            }
            if (flag != '\0') break;
            s_/system/bin/noxspeedup_001152d0[i] =
                 s_/system/bin/noxspeedup_001152d0[i] + (-0x4e - (char)i);
            i = i + 1;
            flag = i == 0x17;
          }
          if (flag != '\x02') {
            do {
                    /* WARNING: Do nothing block with infinite loop */
            } while( true );
          }
        }
        i = pathconf(s_/system/bin/noxspeedup_001152d0,_PC_PRIO_IO);
        return_value = SYSTEM_NOX_NOXSPEEDUP;
        if (i != 0x1000) {
          if (/system/lib/libnoxspeedup.so_decrypted == '\0') {
            i = 0;
            flag = '\0';
            while( true ) {
              while (flag == '\x01') {
                /system/lib/libnoxspeedup.so_decrypted = '\x01';
                flag = '\x02';
              }
              if (flag != '\0') break;
              s_/system/lib/libnoxspeedup.so_001152e7[i] =
                   s_/system/lib/libnoxspeedup.so_001152e7[i] + -0x16;
              i = i + 1;
              flag = i == 0x1d;
            }
            if (flag != '\x02') {
              do {
                    /* WARNING: Do nothing block with infinite loop */
              } while( true );
            }
          }
          i = pathconf(s_/system/lib/libnoxspeedup.so_001152e7,0xb);
          return_value = SYSTEM_LIB_LIBNOXSPEEDUP_SO;
          if (i != 0x1000) {
            if (/system/lib/libnoxd.so_decrypted == '\0') {
              flag = 42;
              i = -0x16;
              uVar1 = 0;
              do {
                k = uVar1;
                cVar2 = s_/system/lib/libnoxd.so_00115304[k];
                s_/system/lib/libnoxd.so_00115304[k] = cVar2 - flag;
                flag = s_/system/lib/libnoxd.so_00115304[k | 1] - (cVar2 - flag);
                s_/system/lib/libnoxd.so_00115304[k | 1] = flag;
                i = i + 2;
                uVar1 = k + 2;
              } while (i != 0);
              cVar2 = '\x01';
              while (cVar2 == '\x01') {
                s_/system/lib/libnoxd.so_00115304[k + 2] =
                     s_/system/lib/libnoxd.so_00115304[k + 2] - flag;
                /system/lib/libnoxd.so_decrypted = '\x01';
                cVar2 = '\x02';
              }
              if (cVar2 != '\x02') {
                do {
                    /* WARNING: Do nothing block with infinite loop */
                } while( true );
              }
            }
            i = pathconf(s_/system/lib/libnoxd.so_00115304,0xb);
            return_value = SYSTEM_LIB_LIBNOXD_SO;
            if (i != 0x1000) {
              return_value = 0;
            }
            return return_value;
          }
        }
      }
    }
  }
  return return_value;
}
```

The files checked in this case are:

* */system/bin/nox-prop*
* */system/bin/noxd*
* */system/bin/nox-vbox-sf*
* */system/bin/noxspeedup*
* */system/lib/libnoxspeedup.so*
* */system/lib/libnoxd.so*

**Check for Qemu files**

Different **Qemu** files checked using **access** API call:

```cpp
bool has_qemu_files(void)
{
  int iVar1;
  bool bVar2;
  
  iVar1 = access(/sys/bus/platform/drivers/qemu_pipe_decrypted,0);
  bVar2 = true;
  if (iVar1 == -1) {
    iVar1 = access(/sys/bus/platform/drivers/qemu_trace_decrypted,0);
    bVar2 = iVar1 != -1;
  }
  return bVar2;
}
```

* /sys/bus/platform/drivers/qemu_pipe
* /sys/bus/platform/drivers/qemu_trace

**Check for virtualbox files**

Checks with **access** API call for detecting **virtualbox** environment:

```cpp
bool has_vbox_files(void)
{
  int iVar1;
  
  iVar1 = access(/dev/vboxguest_decrypted,0);
  if ((((((iVar1 == -1) && (iVar1 = access(/dev/vboxuser_decrypted,0), iVar1 == -1)) &&
        (iVar1 = access(/fstab.vbox86_decrypted,0), iVar1 == -1)) &&
       (((((iVar1 = access(/init.vbox86.rc_decrypted,0), iVar1 == -1 &&
           (iVar1 = access(/system/lib/vboxvideo.ko_decrypted,0), iVar1 == -1)) &&
          ((iVar1 = access(/system/xbin/mount.vboxsf_decrypted,0), iVar1 == -1 &&
           ((iVar1 = access(/ueventd.vbox86.rc_decrypted,0), iVar1 == -1 &&
            (iVar1 = access(/system/lib/hw/audio.primary.vbox86.so_decrypted,0), iVar1 == -1))))))
         && (iVar1 = access(/system/lib/hw/camera.vbox86.so_decrypted,0), iVar1 == -1)) &&
        ((((iVar1 = access(/system/lib/hw/gralloc.vbox86.so_decrypted,0), iVar1 == -1 &&
           (iVar1 = access(DAT_000226bc,0), iVar1 == -1)) &&
          (iVar1 = access(/system/lib/hw/sensors.vbox86.so_decrypted,0), iVar1 == -1)) &&
         ((iVar1 = access(/proc/irq/9/vboxguest_decrypted,0), iVar1 == -1 &&
          (iVar1 = access(/sys/bus/pci/drivers/vboxguest_decrypted,0), iVar1 == -1)))))))) &&
      ((((iVar1 = access(/sys/bus/pci/drivers/vboxguest/0000:00:04.0_decrypted,0), iVar1 == -1 &&
         ((iVar1 = access(/sys/bus/pci/drivers/vboxguest/bind_decrypted,0), iVar1 == -1 &&
          (iVar1 = access(/sys/bus/pci/drivers/vboxguest/module_decrypted,0), iVar1 == -1)))) &&
        ((iVar1 = access(/sys/bus/pci/drivers/vboxguest/new_id_decrypted,0), iVar1 == -1 &&
         ((((iVar1 = access(/sys/bus/pci/drivers/vboxguest/remove_id_decrypted,0), iVar1 == -1 &&
            (iVar1 = access(/sys/bus/pci/drivers/vboxguest/uevent_decrypted,0), iVar1 == -1)) &&
           (iVar1 = access(/sys/bus/pci/drivers/vboxguest/unbind_decrypted,0), iVar1 == -1)) &&
          ((iVar1 = access(/ssys/class/bdi/vboxsf-c_decrypted,0), iVar1 == -1 &&
           (iVar1 = access(/sys/class/misc/vboxguest_decrypted,0), iVar1 == -1)))))))) &&
       ((iVar1 = access(/sys/class/misc/vboxuser_decrypted,0), iVar1 == -1 &&
        ((iVar1 = access(/sys/devices/virtual/bdi/vboxsf-c,0), iVar1 == -1 &&
         (iVar1 = access(/sys/devices/virtual/misc/vboxguest_decrypted,0), iVar1 == -1)))))))) &&
     (((iVar1 = access(/sys/devices/virtual/misc/vboxguest/dev_decrypted,0), iVar1 == -1 &&
       (((iVar1 = access(/sys/devices/virtual/misc/vboxguest/power_decrypted,0), iVar1 == -1 &&
         (iVar1 = access(/sys/devices/virtual/misc/vboxguest/subsystem_decrypted,0), iVar1 == -1))
        && (iVar1 = access(/sys/devices/virtual/misc/vboxguest/uevent_decrypted,0), iVar1 == -1))))
      && ((((iVar1 = access(/sys/devices/virtual/misc/vboxuser_decrypted,0), iVar1 == -1 &&
            (iVar1 = access(/sys/devices/virtual/misc/vboxuser/dev_decrypted,0), iVar1 == -1)) &&
           ((iVar1 = access(/sys/devices/virtual/misc/vboxuser/power_decrypt,0), iVar1 == -1 &&
            ((iVar1 = access(/sys/devices/virtual/misc/vboxuser/subsystem_decrypted,0), iVar1 == -1
             && (iVar1 = access(/sys/devices/virtual/misc/vboxuser/uevent_decrypted,0), iVar1 == -1)
             ))))) &&
          ((iVar1 = access(/sys/module/vboxguest/_decrypted,0), iVar1 == -1 &&
           (((((iVar1 = access(/sys/module/vboxsf/_decrypted,0), iVar1 == -1 &&
               (iVar1 = access(/sys/module/vboxvideo/_decrypted,0), iVar1 == -1)) &&
              (iVar1 = access(/system/lib/vboxpcism.ko_decrypted,0), iVar1 == -1)) &&
             ((iVar1 = access(/system/lib/modules/3.0.8-android-x86+/extra/vboxguest_decrypted,0),
              iVar1 == -1 &&
              (iVar1 = access(/system/lib/modules/3.0.8-android-x86+/extra/vboxguest/vboxguest.ko_de crypted
                              ,0), iVar1 == -1)))) &&
            (iVar1 = access(/system/lib/modules/3.0.8-android-x86+/extra/vboxsf_decrypted,0),
            iVar1 == -1)))))))))) {
    iVar1 = access(/system/lib/modules/3.0.8-android-x86+/extra/vboxsf/vboxsf.ko_decrypted,0);
    if (iVar1 == -1) {
      iVar1 = access(/system/bin/mount.vboxsf_decrypted,0);
      return iVar1 != -1;
    }
    return true;
  }
  return true;
}
```

Next is the list of files checked:

* /dev/vboxguest
* /dev/vboxuser
* /fstab.vbox86
* /init.vbox86.rc
* /system/lib/vboxvideo.ko
* /system/xbin/mount.vboxsf
* /ueventd.vbox86.rc
* /system/lib/hw/audio.primary.vbox86.so
* /system/lib/hw/camera.vbox86.so
* /system/lib/hw/gralloc.vbox86.so
* /system/lib/hw/sensors.vbox86.so
* /proc/irq/9/vboxguest
* /sys/bus/pci/drivers/vboxguest
* /sys/bus/pci/drivers/vboxguest/0000:00:04.0
* /sys/bus/pci/drivers/vboxguest/bind
* /sys/bus/pci/drivers/vboxguest/module
* /sys/bus/pci/drivers/vboxguest/new_id
* /sys/bus/pci/drivers/vboxguest/remove_id
* /sys/bus/pci/drivers/vboxguest/uevent
* /sys/bus/pci/drivers/vboxguest/unbind
* /ssys/class/bdi/vboxsf-c
* /sys/class/misc/vboxguest
* /sys/class/misc/vboxuser
* /sys/devices/virtual/bdi/vboxsf-c
* /sys/devices/virtual/misc/vboxguest
* /sys/devices/virtual/misc/vboxguest/dev
* /sys/devices/virtual/misc/vboxguest/power
* /sys/devices/virtual/misc/vboxguest/subsystem
* /sys/devices/virtual/misc/vboxguest/uevent
* /sys/devices/virtual/misc/vboxuser
* /sys/devices/virtual/misc/vboxuser/dev
* /sys/devices/virtual/misc/vboxuser/power
* /sys/devices/virtual/misc/vboxuser/subsystem_
* /sys/devices/virtual/misc/vboxuser/uevent
* /sys/module/vboxguest/
* /sys/module/vboxsf/
* /sys/module/vboxvideo/
* /system/lib/vboxpcism.ko
* /system/lib/modules/3.0.8-android-x86+/extra/vboxguest
* /system/lib/modules/3.0.8-android-x86+/extra/vboxguest/vboxguest.ko
* /system/lib/modules/3.0.8-android-x86+/extra/vboxsf
* /system/lib/modules/3.0.8-android-x86+/extra/vboxsf/vboxsf.ko
* /system/bin/mount.vboxsf

There's also a check for two *kernel objects* from virtualbox, for obtaining them the command *ls /system/lib* is run:

```cpp
char ** get_lib_files(void)
{
  char **ppcVar1;
  
  ppcVar1 = (char **)exec_command_lines(ls_/system/lib_decrypted);
  return ppcVar1;
}

int has_vbox_files_in_lib(void)

{
  bool bVar1;
  bool bVar2;
  char *pcVar3;
  int iVar4;
  char **ppcVar5;
  int iVar6;
  int iVar7;
  char *pcVar8;
  char **ppcVar9;
  
  ppcVar5 = get_lib_files();
  pcVar3 = vboxguest.ko_decrypted;
  if ((ppcVar5 != (char **)0x0) && (pcVar8 = *ppcVar5, pcVar8 != (char *)0x0)) {
    ppcVar9 = ppcVar5;
    bVar2 = false;
    do {
      ppcVar9 = ppcVar9 + 1;
      iVar6 = strcmp(pcVar3,pcVar8);
      bVar1 = true;
      if (iVar6 != 0) {
        bVar1 = bVar2;
      }
      free(pcVar8);
      pcVar8 = *ppcVar9;
      bVar2 = bVar1;
    } while (pcVar8 != (char *)0x0);
    free(ppcVar5);
    if (bVar1) {
      return CONCAT31((int3)((uint)ppcVar5 >> 8),1);
    }
  }
  ppcVar5 = get_lib_files();
  pcVar3 = vboxsf.ko_decrypted;
  if ((ppcVar5 == (char **)0x0) || (pcVar8 = *ppcVar5, pcVar8 == (char *)0x0)) {
    iVar6 = 0;
  }
  else {
    iVar6 = 0;
    ppcVar9 = ppcVar5;
    do {
      ppcVar9 = ppcVar9 + 1;
      iVar7 = strcmp(pcVar3,pcVar8);
      iVar4 = CONCAT31((int3)((uint)iVar7 >> 8),1);
      if (iVar7 != 0) {
        iVar4 = iVar6;
      }
      iVar6 = iVar4;
      free(pcVar8);
      pcVar8 = *ppcVar9;
    } while (pcVar8 != (char *)0x0);
    free(ppcVar5);
  }
  return iVar6;
}
```

Files checked:

* /system/lib/vboxguest.ko
* /system/lib/vboxsf.ko

**Check for virtio folder**

Check of the **virtio**'s folder to detect hardware acceleration used in android emulation:

```cpp
int has_virtio_folder(void)
{
  DIR *__dirp;
  dirent *pdVar1;
  char *pcVar2;
  int iVar3;
  
  __dirp = opendir(/sys/bus_decrypted);
  if (__dirp == (DIR *)0x0) {
LAB_0001d381:
    iVar3 = 0;
  }
  else {
    do {
      pdVar1 = readdir(__dirp);
      if (pdVar1 == (dirent *)0x0) {
        closedir(__dirp);
        goto LAB_0001d381;
      }
      pcVar2 = strstr(pdVar1->d_name + 8,virtio_decrypted);
    } while (pcVar2 == (char *)0x0);
    iVar3 = CONCAT31((int3)((uint)pcVar2 >> 8),1);
  }
  return iVar3;
}
```

Folder checked:

* /sys/bus/virtio


### Networking checks

Commonly networking from an emulated device is configured in a different way than a real device, also some card interfaces contain names that computers have, it is possible to read network configuration from the path */system/bin/netcfg*, and different values can be checked if they exist:

```java
private boolean checkIp() {
    String[] strArr = {"/system/bin/netcfg"};
    StringBuilder sb = new StringBuilder();
    try {
        ProcessBuilder processBuilder = new ProcessBuilder(strArr);
        processBuilder.directory(new File("/system/bin/"));
        processBuilder.redirectErrorStream(true);
        InputStream inputStream = processBuilder.start().getInputStream();
        byte[] bArr = new byte[1024];
        while (inputStream.read(bArr) != -1) {
            sb.append(new String(bArr));
        }
        inputStream.close();
    } catch (Exception e) {
    }
    String sb2 = sb.toString();
    if (!TextUtils.isEmpty(sb2)) {
        String[] split = sb2.split("\n");
        for (String str : split) {
            if ((str.contains("wlan0") || str.contains("tunl0") || str.contains("eth0")) && str.contains(IP)) {
                return true;
            }
        }
    }
    return false;
}
```


### Check by Package names

Some emulators by default will have

```java
private List<String> mListPackageName = {"com.google.android.launcher.layouts.genymotion", "com.bluestacks", "com.bignox.app"};

private boolean checkPackageName() {
    if (!this.isCheckPackage || this.mListPackageName.isEmpty()) {
        return false;
    }
    PackageManager packageManager = mContext.getPackageManager();
    for (String str : this.mListPackageName) {
        Intent launchIntentForPackage = packageManager.getLaunchIntentForPackage(str);
        if (!(launchIntentForPackage == null || packageManager.queryIntentActivities(launchIntentForPackage, 65536).isEmpty())) {
            return true;
        }
    }
    return false;
}
```


It is possible to detect **koplayer** emulator using the utility **pm** in order to retrieve all the packages installed and checking for **com.koplay.launcher**:

```cpp
char ** pm_apps_installed(void)
{
  char **installed_packages;
  
  installed_packages = (char **)exec_command_lines(pm_list_packages_decrypted);
  return installed_packages;
}

uint has_ko_player_apps_installed(void)
{
  char **apps;
  uint result;
  char **next_app;
  char *app;
  char *index_name;
  
  apps = pm_apps_installed();
  if (apps == (char **)0x0) {
    result = 0;
  }
  else {
    app = *apps;
    result = 0;
    if (app != (char *)0x0) {
      index_name = (char *)0x0;
      next_app = apps;
      do {
        next_app = next_app + 1;
        if (index_name == (char *)0x0) {
          index_name = strstr(app,com.koplay.launcher_decrypted);
        }
        free(app);
        app = *next_app;
      } while (app != (char *)0x0);
      free(apps);
      result = (uint)apps & 0xffffff00 | (uint)(index_name != (char *)0x0);
    }
  }
  return result;
}
```

The next packages could be used to detect **Bluestacks** emulator:

* com.bluestacks.filemanager
* com.bluestacks.appmart
* com.bluestacks.BstCommandProcessor
* com.bluestacks.settings
* com.bluestacks.home
* com.bluestacks.appguidance

And the next for detecting **MEmu App Player**:

* com.microvirt.installer
* com.microvirt.guide
* com.microvirt.tools
* com.microvirt.download
* com.microvirt.memuime
* com.microvirt.launcher
* com.microvirt.launcher2

Packages that will be present in **Nox** emulator:

* com.vphone.googlesign
* com.vphone.helper
* com.vphone.launcher

### Detection of architecture inconsistencies

Using values from the device like the **valueID** or **modelID**, it is possible trying to detect inconsistencies in the architecture

```cpp
int is_arch_inconsistent(void)

{
  bool bVar1;
  char *check1;
  char *check2;
  undefined4 uVar2;
  char *chec3;
  char *check4;
  int iVar3;
  char **value_id_model_id;
  int local_18;
  char **encrypted_values;
  char *p_model_id;
  
  local_18 = __stack_chk_guard;
  value_id_model_id = (char **)0x0;
  bVar1 = _Z12get_cpu_infoPP8cpu_info((char **)&value_id_model_id);
  encrypted_values = value_id_model_id;
  if (bVar1 != true) {
    free_cpu_info((cpu_info **)&value_id_model_id);
    iVar3 = 0;
    goto _end_of_method;
  }
  check1 = strstr(*value_id_model_id,GenuineIntel_decrypted);
  p_model_id = encrypted_values[1];
  check2 = strstr(p_model_id,Virtual_CPU_decrypted);
  if ((check1 == (char *)0x0) || (check2 == (char *)0x0)) {
    if (check1 == (char *)0x0) {
_check_of_inconsistences:
      p_model_id = strstr(*value_id_model_id,AuthenticAMD_decrypted);
      if (p_model_id != (char *)0x0) {
        p_model_id = get_bluestacks_hardware();
        if ((p_model_id == (char *)0x0) || (*p_model_id == '\0')) {
          free(p_model_id);
          p_model_id = (char *)get_ro_boot_hardware();
          if ((p_model_id != (char *)0x0) && (*p_model_id != '\0'))
          goto _check_of_ro_hardware_ro_boot_hardware;
        }
        else {
_check_of_ro_hardware_ro_boot_hardware:
          check1 = strstr(p_model_id,samsungexynos8890_decrypted);
          if ((((check1 != (char *)0x0) ||
               (check1 = strstr(p_model_id,taimen_decrypted), check1 != (char *)0x0)) ||
              (check1 = strstr(p_model_id,qcom_decrypted), check1 != (char *)0x0)) ||
             ((((check1 = strstr(p_model_id,exynos9820_decrypted), check1 != (char *)0x0 ||
                (check1 = strstr(p_model_id,samsungexynos8895_decrypted), check1 != (char *)0x0)) ||
               (check1 = strstr(p_model_id,ttVM_x86_decrypted), check1 != (char *)0x0)) ||
              (check1 = strstr(p_model_id,vbox86_decrypted), check1 != (char *)0x0))))
          goto LAB_0001b58c;
        }
        free(p_model_id);
      }
      free_cpu_info((cpu_info **)&value_id_model_id);
      iVar3 = 0;
      goto _end_of_method;
    }
    check1 = strstr(p_model_id,Xeon_decrypted);
    check2 = strstr(p_model_id,i9_decrypted);
    chec3 = strstr(p_model_id,i7_decrypted);
    check4 = strstr(p_model_id,i5_decrypted);
    p_model_id = strstr(p_model_id,i3_decrypted);
    if ((((check1 == (char *)0x0) && (check2 == (char *)0x0)) && (chec3 == (char *)0x0)) &&
       ((check4 == (char *)0x0 && (p_model_id == (char *)0x0)))) goto _check_of_inconsistences;
    p_model_id = get_bluestacks_hardware();
    if ((p_model_id == (char *)0x0) || (*p_model_id == '\0')) {
      free(p_model_id);
      p_model_id = (char *)get_ro_boot_hardware();
      if ((p_model_id != (char *)0x0) && (*p_model_id != '\0'))
      goto _check_of_ro_hardware_ro_boot_hardware2;
LAB_0001b492:
      free(p_model_id);
      goto _check_of_inconsistences;
    }
_check_of_ro_hardware_ro_boot_hardware2:
    check1 = strstr(p_model_id,samsungexynos8890_decrypted);
    if ((check1 == (char *)0x0) &&
       (((((check1 = strstr(p_model_id,taimen_decrypted), check1 == (char *)0x0 &&
           (check1 = strstr(p_model_id,qcom_decrypted), check1 == (char *)0x0)) &&
          (check1 = strstr(p_model_id,exynos9820_decrypted), check1 == (char *)0x0)) &&
         ((check1 = strstr(p_model_id,samsungexynos8895_decrypted), check1 == (char *)0x0 &&
          (check1 = strstr(p_model_id,ttVM_x86_decrypted), check1 == (char *)0x0)))) &&
        (check1 = strstr(p_model_id,vbox86_decrypted), check1 == (char *)0x0)))) goto LAB_0001b492;
LAB_0001b58c:
    uVar2 = free_cpu_info((cpu_info **)&value_id_model_id);
    free(p_model_id);
  }
  else {
    uVar2 = free_cpu_info((cpu_info **)&value_id_model_id);
  }
  iVar3 = CONCAT31((int3)((uint)uVar2 >> 8),1);
_end_of_method:
  if (__stack_chk_guard != local_18) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return iVar3;
}
```

Possible Values IDs.

* **Value ID**: GenuineIntel
* **Value ID**: AuthenticAMD

Possible Model IDs.

* **Model id**: Virtual CPU
* **Model id**: Xeon
* **Model id**: i9
* **Model id**: i7
* **Model id**: i5
* **Model id**: i3

Values to check from **ro.hardware** and **ro.boot.hardware**:

* **ro.hardware**: samsungexynos8890
* **ro.hardware**: taimen
* **ro.hardware**: qcom
* **ro.hardware**: exynos9820
* **ro.hardware**: samsungexynos8895
* **ro.hardware**: ttVM x86


* **ro.boot.hardware**: samsungexynos8890
* **ro.boot.hardware**: taimen
* **ro.boot.hardware**: qcom
* **ro.boot.hardware**: exynos9820
* **ro.boot.hardware**: samsungexynos8895
* **ro.boot.hardware**: ttVM x86


## References

* [Emulator_Detector.txt](https://github.com/informationextraction/core-android/blob/master/RCSAndroid/doc/Emulator_Detection.txt).
* [Possible files for detecting different emulators](https://github.com/strazzere/anti-emulator/issues/7): strings from an issue in an open source anti-emulator project.
* [FindEmulator.java](https://github.com/strazzere/anti-emulator/blob/master/AntiEmulator/src/diff/strazzere/anti/emulator/FindEmulator.java): Similar project to this library for detecting emulators (this in Java).