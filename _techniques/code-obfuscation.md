---
layout: page
title: Code Obfuscation
nav_order: 6
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

While packing mechanisms try to hide the code through compression and/or encryption of code that will be later extracted and run, code obfuscation hides the real code using *transformation* techniques that takes the clean code and modifies the *control-flow graph*, insert *junk-code*, or insert *code virtualization* in order to make the code much more difficult to understand.

While some packing mechanisms can be defeated through dynamic analysis, dumping the code from memory once it has been loaded, code obfuscation does not dump legit code from the application as this code was transformed to something semantically identical but with a more complex syntax. Both techniques can be used together in order to defeat the dynamic analysis as well as the static analysis.

Code obfuscation can be applied both on Java and Native side, we will mainly focus on the Java part of the program, code obfuscation of native binaries is a well known topic and it's highly covered both in academia and industry, so the discussion for native binaries will be reduced as much as possible. Due to the restrictions in the *Android Runtime (ART)* virtual machine, some of the transformations cannot be applied, because in case of applying them, the code couldn't be run by the virtual machine.

## Techniques

### Identifier Renaming

The *Dalvik code* from Android, when compiled from Java maintain all the symbols from: class names, method names and field names. These names are used as reference for calling methods, or using classes. In programming meaningful names are used to improve code readability, but this information helps analysts or attackers for understanding code.
It is possible to obfuscate the names of these symbols through replacing them in the string table from *DEX* file.

This technique is both used by legit software as well as malicious software, as for example, this obfuscation is offered by *AndroidStudio* using integrated obfuscator in the IDE, then this replacement of symbols can be done in compilation time or when the *APK* has been generated.

Here is an example code of *FluBot* malware which were not obfuscated in the version *1.2*:

```java
public class Utils {
    ...
    public static String GetAppNameFromPackage(Context context, String packageName) {
        try {
            PackageManager packageManager = context.getPackageManager();
            ApplicationInfo info = packageManager.getApplicationInfo(packageName, 128);
            return (String) packageManager.getApplicationLabel(info);
        } catch (Exception e) {
            return null;
        }
    }

    public static boolean AmiDefaultSms(Context context) {
        String defApp = Telephony.Sms.getDefaultSmsPackage(context);
        if (defApp != null && defApp.equals(context.getPackageName())) {
            return true;
        }
        return false;
    }
    ...
}
```

**MD5: c21b46c1b55ce74b5b2a554bf9d86f90**

And in newer versions, they started to apply **identifier renaming** to the samples, here we can find the same code in the version *3.8*:

```java
public class n {
    ...
    public static String e(Context context, String str) {
        try {
            PackageManager packageManager = context.getPackageManager();
            return (String) packageManager.getApplicationLabel(packageManager.getApplicationInfo(str, 128));
        } catch (Exception unused) {
            return null;
        }
    }

    public static boolean a(Context context) {
        String defaultSmsPackage = Telephony.Sms.getDefaultSmsPackage(context);
        return defaultSmsPackage != null && defaultSmsPackage.equals(context.getPackageName());
    }
    ...
}
```

**MD5: 3e3a08826b7c182bb6e3e2c80e9fa231**

### String Encryption

Strings are used in application for different purposes like: showing information to the user, asking for data to the user, printing log messages, etc. The strings are a good information point for an analyst or for an attacker analyzing an application to know what a class or a method is doing. The strings can be hidden using different techniques, the most used ones are: encryption and encoding.

A very common encoding mechanism that can be used is *base64*, all the strings are encoded using algorithm, and decoded in run time. Encryption can range from custom simple algorithms to known encryption algorithms (*AES, RC4, DES, ...*). In both cases, the strings are replaced by calls to a method that will decode or decrypt the string for using it in the code.

Here is an example of the malware *BianLian* which uses many custom decryption algorithms during the whole program:

```java
public class App extends Application {
    ...
    @Override // android.app.Application
    public void onCreate() {
        super.onCreate();
        a = this;
        Thread.setDefaultUncaughtExceptionHandler(new Thread.UncaughtExceptionHandler(this) { // from class: com.pmmynubv.nommztx.App.1
            private static short[] $ = {-17409, -17409, -17409, -17409, -17410, -17507, -17524, -17505, -17523, -17514, -17410};
            final /* synthetic */ App a;

            private static String $(int i, int i2, int i3) {
                char[] cArr = new char[i2 - i];
                for (int i4 = 0; i4 < i2 - i; i4++) {
                    cArr[i4] = (char) ($[i + i4] ^ i3);
                }
                return new String(cArr);
            }

            {
                this.a = this;
            }

            @Override // java.lang.Thread.UncaughtExceptionHandler
            public void uncaughtException(Thread thread, Throwable th) {
                ...
                d.a($(0, 11, -17442) + th.getMessage(), new Object[0]);
                a.b(this.a.getApplicationContext());
                this.a.a(th);
                this.a.a(thread, th);
            }
        });
    }
    ...
}
```

**MD5: 924f353957c8c786a2eeb6422a1bbe3b**

In this example, the technique of **Identifier Renaming** is also used.

Encoding can be found in the malware family *Joker*, the mechanism is based on writing the strings together with unnecessary strings, and use the string method **replace** for eliminating the unnecessary string:

```java
public class oGn1 {

    /* renamed from: oGn1  reason: collision with root package name */
    public static final String f22oGn1 = "htnus35batp".replace("nus35ba", "");
    public static final String azj9 = "Drinus35bazzt".replace("nus35ba", "");
    public static final String HpfJ = "dumnus35bamy0".replace("nus35ba", "");
    public static final String S1h4 = "wlanus35ban0".replace("nus35ba", "");
    public static final String nf66 = "MSnus35baG_FAnus35baILED".replace("nus35ba", "");
    public static final String Xq26 = "enablnus35baed_notificnus35baation_lisnus35bateners".replace("nus35ba", "");
    public static final String l2Xu = "X-Requnus35baested-With".replace("nus35ba", "");
    public static final String FG40 = "Refnus35baerer".replace("nus35ba", "");
    public static final String V0jg = "16nus35ba1.1nus35ba17.4nus35ba6.64".replace("nus35ba", "");
    public static final String FRSq = "4nus35ba7.2nus35ba41.1nus35ba06.26".replace("nus35ba", "");
    public static final String xHpK = "-nus35ba--".replace("nus35ba", "");
    public static final String SIVB = "JBrnus35baidge".replace("nus35ba", "");
    public static final String U9IE = "schenus35badule".replace("nus35ba", "");
    public static final String iCQS = "finnus35baish".replace("nus35ba", "");
    public static final String SDeU = "popMnus35basg".replace("nus35ba", "");
    public static final String usNF = "texnus35batTo".replace("nus35ba", "");
    public static final String bjI2 = "requnus35baest".replace("nus35ba", "");
    public static final String Npty = "prnus35baobe".replace("nus35ba", "");
    public static final String WZgh = "headnus35baers".replace("nus35ba", "");
    public static final String oh94 = "danus35bata".replace("nus35ba", "");
    public static final String xIlk = "unus35barl".replace("nus35ba", "");
    public static final String GheE = "mainFnus35barame".replace("nus35ba", "");
    public static final String oPHk = "bnus35ba64".replace("nus35ba", "");
    public static final String cDje = "UUURnus35baRRLLL".replace("nus35ba", "");
    public static final String JsIn = "dunus35bamp".replace("nus35ba", "");
    public static final String hNMU = "android.provnus35baider.Telnus35baephony.SMnus35baS_RECEIVED".replace("nus35ba", "");
    public static final String ZTaR = "pnus35badus".replace("nus35ba", "");
    public static final String Ffeg = oGn1("window." + SIVB + ".canus35ball('" + JsIn + "',document.documentnus35baElement.outerHTML);");
    public static final String fFLV = "httnus35bap://pornus35batal.bignus35bafunspnus35baace.com/wap/lonus35baad_imnus35baage".replace("nus35ba", "");

    static {
        "mobilnus35bae_data".replace("nus35ba", "");
        "POnus35baST::".replace("nus35ba", "");
        "jp.nanus35baver.line.andnus35baroid".replace("nus35ba", "");
    }

    public static String oGn1(String str) {
        return str.replace("nus35ba", "");
    }
}
```

**MD5: ab676e3aa25c4d16b5d148fd5702cd80**

### CallIndirection

Call indirection technique is based on modifying a direct call to a method, for an indirect way to call that method, this means that a wrapper can be created that internally calls the targeted method. While cross references can be followed for reaching the correct method this takes longer time and in case of manually rename methods and classes during an analysis, it would take longer for an analyst to rename all the methods.

The next example shows a very simple case where this obfuscation is applied, the first code snippets shows the correct code:

```java
class PasswordManager {
    ...
    public void intermediate_fun_0(String password) {
        String good_password = get_password();
        if (password.equals(good_password)) {
            intermediate_fun_1(good_password);
        }
    }

    public void intermediate_fun_1(String password) {
        Log.i(TAG, "intermediate_fun_1");
        intermediate_fun_2(password);
    }

    public void intermediate_fun_2(String password) {
        Log.i(TAG, "intermediate_fun_2");
        leak_password(password);
    }

    public void leak_password(String password) {
        Log.i(TAG, "leak_password");
        Log.i(TAG, password);
        Log.i(TAG, "Leaked!");
    }
    ...
}
```

And now **CallIndirection** is applied to this code, now more methods were created and these have identifiers with random names:

```java
class PasswordManager {
    ...
    public void intermediate_fun_0(String password) {
        String good_password = BYtCRGSEKclpemfo(this);
        if (HstknWHFiLitZHCJ(password, good_password)) {
            ROlbqnkXTqIuVxnm(this, good_password);
        }
    }

    public void intermediate_fun_1(String password) {
        DnEUulZAecfGPvdt(TAG, "intermediate_fun_1");
        ZBYSaLJBnHfwxXTn(this, password);
    }

    public void intermediate_fun_2(String password) {
        AjVTpHFhNCOBaqbW(TAG, "intermediate_fun_2");
        TRpdTXezdNNgyCnT(this, password);
    }

    public void leak_password(String password) {
        wlCLkqZHwAglrEll(TAG, "leak_password");
        dGlVSdmIlgWDyOPj(TAG, password);
        fwwyLJZfurSmjxvo(TAG, "Leaked!");
    }
    ...
}
```

Where the created methods are:

```java
    public static int AjVTpHFhNCOBaqbW(String str, String str2) {
        return Log.i(str, str2);
    }

    public static String BYtCRGSEKclpemfo(PasswordManager passwordManager) {
        return passwordManager.get_password();
    }

    public static int DnEUulZAecfGPvdt(String str, String str2) {
        return Log.i(str, str2);
    }

    public static boolean HstknWHFiLitZHCJ(String str, Object obj) {
        return str.equals(obj);
    }

    public static void ROlbqnkXTqIuVxnm(PasswordManager passwordManager, String str) {
        passwordManager.intermediate_fun_1(str);
    }

    public static void TRpdTXezdNNgyCnT(PasswordManager passwordManager, String str) {
        passwordManager.leak_password(str);
    }

    public static void ZBYSaLJBnHfwxXTn(PasswordManager passwordManager, String str) {
        passwordManager.intermediate_fun_2(str);
    }

    public static int dGlVSdmIlgWDyOPj(String str, String str2) {
        return Log.i(str, str2);
    }

    public static int fwwyLJZfurSmjxvo(String str, String str2) {
        return Log.i(str, str2);
    }

    public static int lEQaPKriXrefSFPL(String str, String str2) {
        return Log.i(str, str2);
    }

    public static int wlCLkqZHwAglrEll(String str, String str2) {
        return Log.i(str, str2);
    }
```

All these wrapper functions make the code less readable, increasing the analysis time.

### Goto insertion

In order to make a more difficult graph, it is possible to insert unconditional jump instructions, because the graph of a method is divided in blocks, these blocks need some type of instructions to mark the end of the block and in this way get the beginning of the next. Injecting *goto* instructions in the code, these basic blocks are divided by that instruction, making it more difficult to follow during an analysis.

The next example shows the insertion of two *goto* instructions, one to the end of the code, and from the end of the code, to the next line after the first *goto*:

```java
.method public static getDebugMessage(Ljava/lang/String;)Ljava/lang/String;
    .registers 3

    const/4 v0, 0x1

    new-array v0, v0, [Ljava/lang/Object;

    const/4 v1, 0x0

    aput-object p0, v0, v1

    const-string p0, "Debug message from %s"

    .line 5
    invoke-static {p0, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0
.end method
```

Now, with two *goto* instructions we would have a jump from the beginning to the end, and from the end to the next line of the first *goto*:

```java
.method public static getDebugMessage(Ljava/lang/String;)Ljava/lang/String;
    .registers 3

    goto/32 :goto_10

    :goto_3
    const/4 v0, 0x1

    new-array v0, v0, [Ljava/lang/Object;

    const/4 v1, 0x0

    aput-object p0, v0, v1

    const-string p0, "Debug message from %s"

    .line 5
    invoke-static {p0, v0}, Ljava/lang/String;->format(Ljava/lang/String;[Ljava/lang/Object;)Ljava/lang/String;

    move-result-object p0

    return-object p0

    :goto_10
    goto/32 :goto_3
.end method
```

While in this example the obfuscation didn't result in a very complicated code, abusing of this technique would create what is commonly known as *spaghetti code*, which could break a decompilation algorithm or optimization algorithms.

### Code reordering

This technique abuse of the previous one (**Goto insertion**) as it changes the order of the basic block in the code, whenever a branch instruction is found condition is inverted and the target basic blocks are reordered. It also re-arrange the code abusing of the *goto* instructions.

### ArithmeticBranch

This technique is inside of the category of *Junk Code Insertion*, in this technique useless and semantic-preserving instructions are added. The arithmetic instructions can be used later for adding conditional branches that depends on the result of the previous instructions. Commonly this technique is used with *Mixed Boolean-Arithmetic* obfuscation, making difficult to calculate statically the value of the condition and if the branch will be taken or not.

### Nop insertion

In this case, the insertion of *No-op* (no operation) instructions is part of the *Junk Code Insertion*, in this case while the code does not increase in complexity, it increases in size. In other architectures the *NOP* instruction is just a symbol of other instructions that do nothing, in this case, instructions which do not affect to program state or the values from the source code can also be used as *NOP* operations, again increasing code in size, but in this case complexity for the analysis can increase.

### Code Virtualization

While this technique is well known in binary obfuscation for other systems (e.g. Windows), and some protectors make use of them (e.g. VMProtect), this is not as known in the bytecode from *Dalvik* virtual machine. A code virtualization protector insert a new *bytecode* interpreter inside of the protected binary, this interpreter will have its own semantic of code, and its *bytecode* will be different to the one of the host binary, this makes that the analyst also needs to understand the semantic of this interpreter, where each possible instruction will have one or more handlers as well as possibly its own architecture, two architectures commonly are used:

* Stack based: where the operators from the instructions are pushed into a virtual stack, operations are applied to the top of the stack, and finally results will be present also in the top of the stack. A virtual register is commonly used for pointing to the top of the virtual stack.
* Register based: in this case the interpreter instead of having a buffer that will be used as stack, it will contain a structure of virtual registers, these registers are used in the interpreter instructions.

In both cases, a buffer should contain the *bytecode*, result of *recompiling* the real instructions into the new Instruction Set Architecture (*ISA*). Commonly one virtual register is always used to point to the *bytecode* to run.

Finally the handlers for the instructions are commonly implemented inside of a *switch* that interprets the bytes from the *ISA*.

In the code from [3] we can find a very good example of this technique, one of the classes implement the handlers for different byte codes, these handlers make use of different stacks of different variable types, next we can see part of the code:

```java
class PCodeVM {
    public PCodeVM(Object arg3, Object arg4) {
        this.istk = new int[12];
        this.jstk = new long[12];
        this.fstk = new float[12];
        this.dstk = new double[12];
        this.lstk = new Object[12];
        this.lstk[5] = arg3;
        this.lstk[6] = arg4;
        this.stkidx = 0;
        this.peekidx = -1;
    }

    public int exec(int opcode) {
        int v0 = 1;
        switch(opcode) {
            case 1: {
                int v2 = this.stkidx;
                this.stkidx = v2 + 1;
                this.lstk[v2] = this.lstk[6];
                int v3 = this.stkidx - 1;
                Object v0_1 = this.lstk[this.stkidx - 1];
                this.lstk[this.stkidx - 1] = null;
                this.istk[v3] = ((byte[])v0_1).length;
                this.lstk[this.stkidx - 1] = new byte[this.istk[this.stkidx - 1]];
                return 0;
            }
            case 2: {
                --this.stkidx;
                Object v3_1 = this.lstk[this.stkidx];
                this.lstk[this.stkidx] = null;
                this.lstk[7] = v3_1;
                return 0;
            }
            ...
            case 54: {
                int v2_40 = this.stkidx;
                this.stkidx = v2_40 + 1;
                this.istk[v2_40] = this.istk[11];
                int v2_41 = this.stkidx;
                this.stkidx = v2_41 + 1;
                this.lstk[v2_41] = this.lstk[6];
                int v3_14 = this.stkidx - 1;
                Object v0_14 = this.lstk[this.stkidx - 1];
                this.lstk[this.stkidx - 1] = null;
                this.istk[v3_14] = ((byte[])v0_14).length;
                return 0;
            }
            case 55: {
                break;
            }
            default: {
                return opcode;
            }
        }

        this.stkidx += -2;
        if(this.istk[this.stkidx] >= this.istk[this.stkidx + 1]) {
            v0 = 0;
        }

        this.b = v0;
        return 0;
    }
}
```

Then we have a class that was *recompiled* and virtualized following the *ISA* of this VM:

```java
class VClass {
    public VClass(Context ctx, byte[] key) {
        this.sbox = new byte[0x100];
        this.tbox = new byte[0x100];
        this.ctx = ctx;
        if(key.length <= 0 || key.length > 0x100) {
            throw new IllegalArgumentException("illegal key length");
        }

        this.keylen = key.length;
        int i;
        for(i = 0; i < 0x100; ++i) {
            this.sbox[i] = (byte)i;
            this.tbox[i] = key[i % this.keylen];
        }

        int j = 0;
        int k = 0;
        while(j < 0x100) {
            k = this.sbox[j] + k + this.tbox[j] & 0xFF;
            byte v0 = this.sbox[k];
            this.sbox[k] = this.sbox[j];
            this.sbox[j] = v0;
            ++j;
        }
    }

    // virtualized method, likely doing encryption/decryption
    public final byte[] d(byte[] arg10) {
        PCodeVM vm = new PCodeVM(this, arg10);
        int[] pcode = {-1, 1, 2, 3, 4, 5, -2, 7, -3, -4, 9, 10, 13, -5, 14, 13, -6, -7, -8, 16, -9, 17, -9, 18, -10, 19, -11, 20, 21, 22, 23, 24, 25, -12, 26, -10, -13, 27, 28, 13, -14, 14, 13, -15, -16, -17, -18, 14, 14, 13, 0x1F, -19, 14, 14, 13, 0x1F, -12, -8, -20, -17, 0x20, 33, 34, 35, 36, -21, 39, 40, 41, 42, 43, -21, 44, 35, 36, -21, 45, 46, 0x2F, 36, -21, 46, 0x30, 36, -21, 46, 49, -21, 50, 41, 51, 36, -21, 22, 52, 53, 13, -22, -23, -24, 54, -25, -26, -27};
        int idx = 0;
    next:
        int idx1 = idx + 1;
        switch(vm.exec(pcode[idx])) {
            case -27: {
                idx = 34;
                goto next;
            }
            case -26: {
                idx = 23;
                goto next;
            }
            case -25: {
                vm.exec(55);
                if(vm.intLoaded == 0) {
                    idx = 103;
                    goto next;
                }

                idx = idx1;
                goto next;
            }
            ...
            case -4: {
                vm.intStored = 0;
                vm.exec(8);
                idx = idx1;
                goto next;
            }
            case -3: {
                vm.exec(6);
                return (byte[])vm.objLoaded;
            }
            case -2: {
                idx = 36;
                goto next;
            }
            case -1: {
                idx = 0x2F;
                goto next;
            }
            default: {
                idx = idx1;
                goto next;
            }
        }
    }
}
```

We can see that the buffer:

```java
int[] pcode = {-1, 1, 2, 3, 4, 5, -2, 7, -3, -4, 9, 10, 13, -5, 14, 13, -6, -7, -8, 16, -9, 17, -9, 18, -10, 19, -11, 20, 21, 22, 23, 24, 25, -12, 26, -10, -13, 27, 28, 13, -14, 14, 13, -15, -16, -17, -18, 14, 14, 13, 0x1F, -19, 14, 14, 13, 0x1F, -12, -8, -20, -17, 0x20, 33, 34, 35, 36, -21, 39, 40, 41, 42, 43, -21, 44, 35, 36, -21, 45, 46, 0x2F, 36, -21, 46, 0x30, 36, -21, 46, 49, -21, 50, 41, 51, 36, -21, 22, 52, 53, 13, -22, -23, -24, 54, -25, -26, -27};
```

It is the recompiled method using the new *bytecode*, the variable *idx* is the program counter of this method.

### Control Flow Flattening

This technique tries to obfuscate the *call-flow graph* of a program into a single function, the hidden functions will be transformed into basic blocks, and these basic blocks will be joined all into a big function, this function will implement a *switch* instruction. The *switch* statement to execute will be decided depending on the position of the functions in the *call-flow graph*, once the switch statement has finished, the identifier for the next statement will be set in a variable that works as *program counter* and the *switch* instruction will be run again in a loop. This technique is the one commonly use as a base in the previous obfuscation (**Code Virtualization**).
While he had a code snippet in previous obfuscation, in the next image we can see how it looks a compiled *control flow flattening* obfuscation, lifted to a higher language (IR) and generated its *control-flow graph*:

![Control Flow Flattening](./images/control-flow-flattening.png)

## References

* [Understanding Android Obfuscation Techniques: A Large-Scale Investigation in the Wild](https://link.springer.com/chapter/10.1007/978-3-030-01701-9_10)
* [Obfuscapk: An open-source black-box obfuscation tool for Android apps](https://www.sciencedirect.com/science/article/pii/S2352711019302791?via%3Dihub)
* [Reversing android protector virtualization](https://www.pnfsoftware.com/blog/reversing-android-protector-virtualization/)