---
layout: page
title: Anti-Disassembly and Decompilation
nav_order: 4
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

Disassembly and decompilation are two powerful tools in the analyst's belt as it allows to inspect the internals of an executable file (*EXE, ELF, DEX*), a disassembler reads the bytes from the binary and tries to interpret them for obtaining instructions from one computer architecture, in the case of *DEX* binary format this work is commonly simpler to disassemble as each method contains its own bytes, and in other formats like *ELF* or *EXE*, all the executable bytes are commonly contained in a *.text* section, and it's necessary to apply algorithms to recognizes functions in the binary.

Two algorithms are commonly used for disassembly a binary: *linear sweep* and *recursive disassembly*. The former goes from the first to the last byte disassembling each instruction, and the latter takes a starting point (commonly binary entry point) and follows the control flow to disassembly the instructions. Newer algorithm exists that join both algorithms (*speculative disassembly*).
Once the code has been disassembled, there are algorithms to obtain the bounders of the functions, with these algorithms there's a best effort to obtain the functions of the binary, commonly fixed patterns or analysis of control flows are used to obtain these boundaries.

A decompiler is a step forward where previous discovered functions are taken and using different techniques common patterns from high level languages (conditional code like *if*, *if-else*, loops like *while* or *for*, etc) are recognized and a pseudo-code is generated making the analysis simpler.

Due to how these algorithms work it's possible to use different flaws or write specially crafted code that breaks the logic of the algorithm and produces incorrect code.

## Techniques

### Incorrect Opcodes

While Dalvik contains a large set of opcodes in its bytecode that define the instructions to run, this set is not as long as other ISAs like x86 or x86-64 where there are many combination of opcodes to create the different instructions. A Disassembler for Dalvik will take the bytecode defined for each method and will try to disassemble all the bytes from the first to the last one, the first opcode is commonly used to detect the type of instruction, and the other bytes from the instruction (the length depends on the instruction format), will be used to detect parameters like registers, fields used, strings accessed, classes, etc. While Dalvik machine or currently ART will not run incorrect instructions, is possible that a protector modifies these bytes before are interpreted, and in the *classes.dex* file have an incorrect set of bytes.

The next example corresponds to a sample with MD5 *78888acc8f2e5b0d59f91ad3b5f6afee*:

```
**************************************************************
* Landroid/support/0RxDAGZKgW2jP4O8XMSGzp8cOHObsCyTp4c1Un... *
*                                                            *
* Instruction Bytes: 0x22                                    *
* Registers Size: 0x2                                        *
* Incoming Size: 0x1                                         *
* Outgoing Size: 0x0                                         *
* Tries Size: 0x0                                            *
*                                                            *
**************************************************************
00463bf0 02 00 01        code_ite
        00 00 00 
        00 00 65 
00463bf0 02 00           dw        2h                      registers_size
00463bf2 01 00           dw        1h                      ins_size
00463bf4 00 00           dw        0h                      outs_size
00463bf6 00 00           dw        0h                      tries_size
00463bf8 65 b4 3e 00     ddw       3EB465h                 debug_info_off
00463bfc 11 00 00 00     ddw       11h                     insns_size
00463c00 00 c2 a7 1c 13  dw[17]                            insns
        67 1d 82 4a bb 
        45 a8 1b 82 4c
    00463c00 [0]             C200h,  1CA7h,  6713h,  821Dh
    00463c08 [4]             BB4Ah,  A845h,  821Bh,  264Ch
    00463c10 [8]             9948h,  6927h,  671Bh,  1EAEh
    00463c18 [12]            206Bh,  5559h,  1EA0h,  B567h
    00463c20 [16]            7D8Ch
00463c22 00 00           dw        0h                      padding
```

The next buffer corresponds to the bytes of the instructions:

```
00 c2 a7 1c 13 67 1d 82 4a bb 45 a8 1b 82 4c 26 48 99 27 69 1b 67 ae 1e 6b 20 59 55 a0 1e 67 b5 8c 7d
```

The parser will start reading the first bytes, the byte 0x00 corresponds to the instructions format: *Instruction10x*, *FillArrayData*, *PackedSwitch* and *SparseSwitch*. But as the second byte is not 0x01, 0x02 or 0x03, this instruction should be the format *Instruction10x* being in this case a **NOP** instruction.

The format of the instruction *Instruction10x* requires that the second byte must be 0x00, and because in this case is another value (0xC2), the disassembler doesn't understand the instruction. And it's disassembler's work to recover or just skip those bytes for working.

In the case of *jadx* the disassembler generates a **NOP**, but later during the disassembly of the method, it crashes:

```
.method public JTOhbpONI5DyGC9b1eFzkaeNVyp6mL0Ra4eKLhYVjiJFA4wP0A2oox5m06CwbJ1Ks6o9PsuKisOuqncbe5d6FdV7siv3scfMz3ixhUTbhq2W3dF0dJrPC9XBrn3Ww37VFaGPQnmWzqaLdqe1jwDZu0Si4ZUByWrZeBbOrPAMr9J63Xelz6BB()I
    .registers 2

    .prologue
    .line 7
    #unknown opcode: 0xc200
    nop

    sub-float p27, p18, p102

    monitor-enter p129

    aget-short p186, p68, p167

Error generating smali code: Encountered small uint that is out of range at offset 0x463c0e
org.jf.util.ExceptionWithContext: Encountered small uint that is out of range at offset 0x463c0e
...
```

In the case of *apktool* we have a similar behavior, it changes the unknown instructions for *nop*, but in the case of those methods that generated exception it does not generate the smali of the class.

*Ghidra* takes **NOP** operation as a single byte instruction, and then it continues disassembling the methods.

This technique while it would not be possible without modifying the bytecode before the execution, it's very powerful against disassembling and because the method cannot obtain a good disassembled code, against decompilation.

## References

* [Issue 224 Jadx Anti-disassemble tricks with illegal opcodes totally break JADX decompilation](https://github.com/skylot/jadx/issues/224).
* [Issue 199 Jadx Jadx fails when handling obfuscated code](https://github.com/skylot/jadx/issues/199)
* [How to Break Your JAR in 2021 - Decompilation Guide for JARs and APKs](https://www.eiken.dev/blog/2021/02/how-to-break-your-jar-in-2021-decompilation-guide-for-jars-and-apks/)
* [Error when decompiling: Error occurred while disassembling class Landroid.support.multiex.MultiDex$V14; - skipping class #2316](https://github.com/iBotPeaches/Apktool/issues/2316)