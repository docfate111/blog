---
layout: post
title:  SLUB overflow CVE-2021-42327
date:   2021-11-07 18:32:13 -0700
categories: SecurityResearch
---

# Introduction

This bug is kind of useless except if the specific driver is present, the debug fs is enabled, and the debugfs is somehow not root. 
I didn't have the gaming laptop or GPU for this specific driver so I just copied the vulnerable function and function it is used in into QEMU for exploiting.
The vulnerability was introduced somewhere in the Linux Kernel 5.8-rc2 branch and fixed in [5.14.15](https://patchwork.freedesktop.org/patch/461554/?series=96341&rev=2). I found it by auditing the source for a long time.

# Vulnerability

The bug is to quote Specter from the Day[0] podcast: "pretty lame". Three basic heap overflows in two in kmalloc-64 and one in kmalloc-128 SLUB.
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
And then within the function the copy from userspace happens:

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

For the exploit I am using the default [KASLR](https://en.wikipedia.org/wiki/Address_space_layout_randomization), [SMEP](https://j00ru.vexillium.org/2011/06/smep-what-is-it-and-how-to-beat-it-on-windows/), [SMAP](https://en.wikipedia.org/wiki/Supervisor_Mode_Access_Prevention), and [KPTI](https://en.wikipedia.org/wiki/Kernel_page-table_isolation). Enabling SELinux wouldn't effect the exploit but it would actually make it easier since the security pointer in msg_msg can be used for KASLR leak.

# Exploitation

# Information leak/KASLR bypass


