---
layout: page
title: Program Loading Abuse
nav_order: 7
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

Both malicious and legit applications make use of dynamic loading techniques in order to hide as much as possible the program's code, the basic of the technique is including an initial DEX that is loaded into memory first and use that initial DEX for decrypting and loading a second component (e.g. DEX, JAR or APK file). This make that static analysis tools cannot extract any information from the real code.

## Techniques

### Replacement of default application *loader*

When an application is going to be loaded in memory, there's an *Android* specific loader that takes care of loading the **main** Activity specified in the *AndroidManifest.xml*, the system allows a programmer to replace it with its own *loader*. This mean that even before the **main** Acitivity is loaded in memory, there will be application code running, and most of the programs which do code loading use this moment for loading the real *DEX* file just before the **main** Activity is run.

For doing this, the application needs to specify a class in the *AndroidManifest.xml* in the *\<Application\>* tag. Varios malware families apply this trick, so their real functionality is loaded in run time, first decrypting and/or decompressing the file, and finally loading the new DEX in memory.

We can find this in the version *3.0* of **FluBot**:

```xml
<application android:theme="@style/Theme.MyApplicationTest" android:label="@string/app_name" android:icon="@drawable/icon" android:name="com.mcal.apkprotector.ProxyApplication" android:debuggable="false" android:allowBackup="true" android:supportsRtl="true" android:extractNativeLibs="false" android:usesCleartextTraffic="true" android:appComponentFactory="androidx.core.app.CoreComponentFactory">
```

Where the class *com.mcal.apkprotector.ProxyApplication* is in charge of loading the encrypted *DEX* file.

Or for example, in case of **BianLian**, we can see the next:

```xml
<application obfuscation:theme="@style/AppTheme" obfuscation:label="Video Player" obfuscation:icon="@mipmap/ic_launcher" obfuscation:name="com.brazzers.naughty.g" obfuscation:allowBackup="true" obfuscation:supportsRtl="true">
```

In this case the class that will load the other *DEX* file is *com.brazzers.naughty.g*.

In both cases the techniques used for loading the *DEX* file once this has been decrypted and/or decompressed will be explained here too.

### loadDexFile

*Android* API method to load a *DEX* file directly in memory, internally it creates an instance of a **DexFile** object and then it will load it into memory, this method receive the file path as parameter:

```java
/**
 * Constructs a {@code DexFile} instance, as appropriate depending
 * on whether {@code optimizedDirectory} is {@code null}.
 */
private static DexFile loadDexFile(File file, File optimizedDirectory)
        throws IOException {
    if (optimizedDirectory == null) {
        return new DexFile(file);
    } else {
        String optimizedPath = optimizedPathFor(file, optimizedDirectory);
        return DexFile.loadDex(file.getPath(), optimizedPath, 0);
    }
}
```

### makePathElements & makeDexElements

In this method for loading *DEX* files the *Android* API methods **makePathElements** or **makeDexElements**, these methods receive a list of *DEX* files as parameter, and internally the method **makeDexElements** load the DEX files calling **loadDexFile**, this can be obtained from *AOSP* source code:

```java
@UnsupportedAppUsage
@SuppressWarnings("unused")
private static Element[] makePathElements(List<File> files, File optimizedDirectory,
        List<IOException> suppressedExceptions) {
    return makeDexElements(files, optimizedDirectory, suppressedExceptions, null);
}

@UnsupportedAppUsage
private static Element[] makeDexElements(List<File> files, File optimizedDirectory,
        List<IOException> suppressedExceptions, ClassLoader loader) {
    return makeDexElements(files, optimizedDirectory, suppressedExceptions, loader, false);
}

private static Element[] makeDexElements(List<File> files, File optimizedDirectory,
        List<IOException> suppressedExceptions, ClassLoader loader, boolean isTrusted) {
    Element[] elements = new Element[files.size()];
    int elementsPos = 0;
    /*
    * Open all files and load the (direct or contained) dex files up front.
    */
    for (File file : files) {
        if (file.isDirectory()) {
            // We support directories for looking up resources. Looking up resources in
            // directories is useful for running libcore tests.
            elements[elementsPos++] = new Element(file);
        } else if (file.isFile()) {
            String name = file.getName();
            DexFile dex = null;
            if (name.endsWith(DEX_SUFFIX)) {
                // Raw dex file (not inside a zip/jar).
                try {
                    dex = loadDexFile(file, optimizedDirectory, loader, elements);
                    if (dex != null) {
                        elements[elementsPos++] = new Element(dex, null);
                    }
                } catch (IOException suppressed) {
                    System.logE("Unable to load dex file: " + file, suppressed);
                    suppressedExceptions.add(suppressed);
                }
            } else {
                try {
                    dex = loadDexFile(file, optimizedDirectory, loader, elements);
                } catch (IOException suppressed) {
                    /*
                    * IOException might get thrown "legitimately" by the DexFile constructor if
                    * the zip file turns out to be resource-only (that is, no classes.dex file
                    * in it).
                    * Let dex == null and hang on to the exception to add to the tea-leaves for
                    * when findClass returns null.
                    */
                    suppressedExceptions.add(suppressed);
                }
                if (dex == null) {
                    elements[elementsPos++] = new Element(file);
                } else {
                    elements[elementsPos++] = new Element(dex, file);
                }
            }
            if (dex != null && isTrusted) {
            dex.setTrusted();
            }
        } else {
            System.logW("ClassLoader referenced unknown path: " + file);
        }
    }
    if (elementsPos != elements.length) {
        elements = Arrays.copyOf(elements, elementsPos);
    }
    return elements;
}
```

This technique is used in the *Android* malware **BianLian** (deobfuscated code snippet):

```java
private static void load_dex_file(ClassLoader classLoader, File file, List<? extends File> list) {
    IOException[] iOExceptionArr;
    if (!list.isEmpty()) {
        Object pathList = get_field_by_name(classLoader, "pathList").get(classLoader);
        ArrayList arrayList = new ArrayList();
        String dexElements = decryption_method(3279);
        Object[] makePathElements_output = (Object[]) (Build.VERSION.SDK_INT >= 23 ? get_method_by_name(pathList, "makePathElements", List.class, File.class, List.class) : get_method_by_name(pathList, "makeDexElements", ArrayList.class, File.class, ArrayList.class)).invoke(pathList, new ArrayList(list), file, arrayList);
        Field dexElements_field = get_field_by_name(pathList, dexElements);
        Object[] objArr = (Object[]) dexElements_field.get(pathList);
        Object[] dexElementsToInstall = (Object[]) Array.newInstance(objArr.getClass().getComponentType(), objArr.length + makePathElements_output.length);
        System.arraycopy(objArr, 0, dexElementsToInstall, 0, objArr.length);
        System.arraycopy(makePathElements_output, 0, dexElementsToInstall, objArr.length, makePathElements_output.length);
        dexElements_field.set(pathList, dexElementsToInstall);
        if (arrayList.size() > 0) {
            Iterator it = arrayList.iterator();
            while (it.hasNext()) {
                it.next();
                // Exception in makeDexElement
            }
            Field dexElementsSuppressedExceptions = get_field_by_name(pathList, "dexElementsSuppressedExceptions");
            IOException[] iOExceptionArr2 = (IOException[]) dexElementsSuppressedExceptions.get(pathList);
            if (iOExceptionArr2 == null) {
                iOExceptionArr = (IOException[]) arrayList.toArray(new IOException[arrayList.size()]);
            } else {
                IOException[] iOExceptionArr3 = new IOException[arrayList.size() + iOExceptionArr2.length];
                arrayList.toArray(iOExceptionArr3);
                System.arraycopy(iOExceptionArr2, 0, iOExceptionArr3, arrayList.size(), iOExceptionArr2.length);
                iOExceptionArr = iOExceptionArr3;
            }
            dexElementsSuppressedExceptions.set(pathList, iOExceptionArr);
            throw new IOException("I/O exception during makeDexElement", (Throwable) arrayList.get(0));
        }
    }
}
```

### Abuse of ART Loading Mechanism

The Android code is stored in a *Dalvik Bytecode* format inside of the *DEX* files, the Android system can run this code in two different ways, the code can be interpreted (where a virtual machine will run different methods that emulates the Dalvik Instructions), or the code can be run in case this was compiled Ahead-of-Time. Before a method from *Dalvik code* can be run, its class must be loaded into memory by the *ART* virtual machine.

Once the *ART* VM has loaded the class into a *dex::ClassDef* object, its attributes and methods are loaded by the function *ClassLinker::LoadClass*, a packer can take advantage of this in order to load classes in memory from *native* side, the *DEX* file can contain corrupted structures, and once a native library is loaded, this can fix the *DEX* structures corresponding to *headers (header_items)*, *classes (class_def_items)* and *methods (encoded_methods)*, then directly load them in memory using the internal mechanisms.

Some of the Java classes are represented by various runtime objects, this runtime objects are compiled classes from *C++* and can be manipulated in order to fix corrupted structures before these are loaded into memory. So for example an *encoded_method* is an instance of an *ArtMethod* object, if the *encoded_method* contains a crafted structure, before it is loaded into memory with *ClassLinker::LoadMethod*, a protector could hook this method, retrieve the parameter with the *ArtMethod* and fix it for loading a correct *Dalvik* method into memory.

These techniques are referenced with the names of **Dynamic Dex Data Modification (DDM)** and **Dynamic Runtime Object Modification (DOM)** in [3].

The complete loading mechanism of classes and methods, and the execution of the *Dalvik* methods is explained in [2].

## References

* [Android/BianLian payload](https://cryptax.medium.com/android-bianlian-payload-61febabed00a)
* [Application of ART in Android Security Attack and Defense](https://evilpan-com.translate.goog/2021/12/26/art-internal/?_x_tr_sl=auto&_x_tr_tl=en&_x_tr_hl=en#art)
* [Happer: Unpacking Android Apps via a Hardware-Assisted Approach](http://yajin.org/papers/sp21_happer.pdf)