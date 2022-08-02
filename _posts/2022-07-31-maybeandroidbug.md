---
layout: post
title:  Potential Android driver race condition
date:   2022-07-31 18:32:13 -0700
categories: SecurityResearch
---

# Introduction

I got a new phone and since I had some time in the summer between finals and my internship I decided to look for bugs in the code via auditing the [source](https://opensource.samsung.com/uploadSearch?searchValue=SM-A136).
I mainly just looked at custom drivers for the Linux kernel. I don't know if this code is actually used in the phone but there is a character driver file /dev/audio_ipi on some devices(i.e. checking with adb shell on my old phone).
Initially I thought the bug wasn't there since I couldn't trigger a crash in qemu(I took the vulnerable code and [removed some code to emulate it](https://github.com/docfate111/testing_android_driver)) but after I increased the number of cores from 1 to 2 the PoC crashed the kernel.
The bug requires capabalities to interact with the driver and somehow escaping the Android sandbox. The main reason I am not sure if the driver is 
used in any Android devices is that the code requires specific hardware and is written as a framework to add functionality to.

# Vulnerability

The main bug is that there is a global array that is used without any synchronization primitives in the ioctl so the user can cause a crash and possible leak memory or get code execution.

The ioctl in drivers/misc/mediatek/audio_ipi/common/framework/audio_ipi_driver.c
```
569 static long audio_ipi_driver_ioctl(
570         struct file *file, unsigned int cmd, unsigned long arg)
571 {
...
582         switch (cmd) {
...
629         case AUDIO_IPI_IOCTL_REG_DMA: {
630                 if (((void __user *)arg) == NULL) {
631                         retval = -1;
632                         break;
633                 }
634                 retval = copy_from_user(
635                                  &dma_reg,
636                                  (void __user *)arg,
637                                  sizeof(struct audio_ipi_reg_dma_t));
638                 if (retval != 0) {
639                         pr_notice("dma reg copy_from_user retval %d", retval);
640                         break;
641                 }
642                 check_sum = dma_reg.magic_footer + dma_reg.magic_header;
643                 if (check_sum != 0xFFFFFFFF) {
644                         pr_notice("dma reg check fail! header(0x%x) footer(0x%x)",
645                                   dma_reg.magic_header,
646                                   dma_reg.magic_footer);
647                         retval = -1;
648                         break;
649                 }
650 
651                 if (dma_reg.reg_flag)
652                         retval = audio_ipi_dma_alloc_region(dma_reg.task,
653                                                             dma_reg.a2d_size,
654                                                             dma_reg.d2a_size);
655                 else
656                         retval = audio_ipi_dma_free_region(dma_reg.task);
657 
658                 break;
659         }
```
There is a sanity check that userspace can easily satisfy and then based on reg_flag the user sets
The function either frees or allocates a DMA region with the first fit gen_pool allocator.

In drivers/misc/mediatek/audio_ipi/common/framework/audio_ipi_dma.c:
```
582 int audio_ipi_dma_alloc_region(const uint8_t task,
583                                const uint32_t ap_to_dsp_size,
584                                const uint32_t dsp_to_ap_size)
 ...
                 for (i = 0; i < NUM_AUDIO_IPI_DMA_PATH; i++) {
643                 if (size[i] == 0) {
644                         pr_debug("task %d, size[%d]: %u", task, i, size[i]);
645                         continue;
646                 }
647 
648                 region = &g_dma[dsp_id]->region[task][i];
649 
650                 new_addr = gen_pool_alloc(g_dma_pool[dsp_id], size[i]);
...
661                 phy_value = gen_pool_virt_to_phys(g_dma_pool[dsp_id], new_addr);
662                 if (phy_value == 0) {
663                         pr_notice("task %d, gen_pool_virt_to_phys() fail, g_dma_pool[%u] %p, new_addr %zu",
664                                   task,
665                                   dsp_id,
666                                   g_dma_pool[dsp_id],
667                                   new_addr);
668                         WARN_ON(1);
669                         ret = -ENOMEM;
670                         break;
671                 }
672 
673                 region->offset = phy_addr_to_offset(phy_value, dsp_id);
674                 region->size = size[i];
675                 region->read_idx = 0;
676                 region->write_idx = 0;
...
714 int audio_ipi_dma_free_region(const uint8_t task)
715 {
758         for (i = 0; i < NUM_AUDIO_IPI_DMA_PATH; i++) {
759                 region = &g_dma[dsp_id]->region[task][i];
760 
761                 if (region->read_idx != region->write_idx) {
762                         pr_notice("region[%d][%d]: %u != %u",
763                                   task, i, region->read_idx, region->write_idx);
764                 }
765                 if (region->size == 0) {
766                         AUD_ASSERT(region->offset == 0);
767                         continue;
768                 }
769                 phy_value = offset_to_phy_addr(region->offset, dsp_id);
770                 ipi_dbg("task %d, region[%d] sz 0x%x, offset 0x%x, phy_value 0x%x",
771                         task, i, region->size, region->offset, phy_value);
772 
773                 gen_pool_free(g_dma_pool[dsp_id],
774                               phy_addr_to_vir_addr_val(phy_value, dsp_id),
775                               region->size);
776 
777                 region->offset = 0;
778                 region->size = 0;
779                 region->read_idx = 0;
780                 region->write_idx = 0;
781         }
```
g_dma_pool and g_dma are global arrays.

Uh oh.

Both audio_ipi_dma_alloc_region and audio_ipi_dma_free_region reads and writes from two global arrays: g_dma and g_dma_pool which are 
also being read and written to by other functions that can also be running at the same time.

Maybe we could also call another function from the ioctl in drivers/misc/mediatek/audio_ipi/common/framework/audio_ipi_driver.c
at the same time:
```
569 static long audio_ipi_driver_ioctl(
570         struct file *file, unsigned int cmd, unsigned long arg)
571 {
...
582         switch (cmd) {
583         case AUDIO_IPI_IOCTL_SEND_MSG_ONLY: {
584                 retval = parsing_ipi_msg_from_user_space(
585                                  (void __user *)arg, AUDIO_IPI_MSG_ONLY);
586                 break;
587         }
588         case AUDIO_IPI_IOCTL_SEND_PAYLOAD: {
589                 retval = parsing_ipi_msg_from_user_space(
590                                  (void __user *)arg, AUDIO_IPI_PAYLOAD);
591                 break;
592         }
593         case AUDIO_IPI_IOCTL_SEND_DRAM: {
594                 retval = parsing_ipi_msg_from_user_space(
595                                  (void __user *)arg, AUDIO_IPI_DMA);
596                 break;
```
Let's go with AUDIO_IPI_IOCTL_SEND_MSG_ONLY, AUDIO_IPI_IOCTL_SEND_PAYLOAD, or AUDIO_IPI_IOCTL_SEND_DRAM
which would call parsing_ipi_msg_from_user_space and this calls audio_ipi_dma_write_region which calls audio_region_write_from_linear
In audio_ipi_dma_write_region in the file drivers/misc/mediatek/audio_ipi/common/framework/audio_ipi_dma.c
```
1131 int audio_ipi_dma_write_region(const uint8_t task,
1132                                const void *data_buf,
1133                                uint32_t data_size,
1134                                uint32_t *write_idx)
...
1163         region = &g_dma[dsp_id]->region[task][AUDIO_IPI_DMA_AP_TO_SCP]; // AUDIO_IPI_DMA_AP_TO_SCP is 0
1164         DUMP_REGION(ipi_dbg, "region", region, data_size);
1165         
1166         /* keep the data index before write */
1167         *write_idx = region->write_idx;
1168         
1169         /* write data */
1170         ret = audio_region_write_from_linear(dsp_id, 
1171                                              region, data_buf, data_size);
```
Region is usercontrolled since g_dma[dsp_id]->region[task][0] can be edited.
```
890 static int audio_region_write_from_linear(uint32_t dsp_id,
891                 struct audio_region_t *region,
892                 const void *linear_buf,
893                 uint32_t count)
894 {
...
922         if (region->size == 0) {
923                 DUMP_REGION(pr_notice, "size fail", region, count);
924                 return -ENODEV;
925         }
926 
927         if (region->read_idx >= region->size) {
928                 DUMP_REGION(pr_notice, "read_idx fail", region, count);
929                 region->read_idx %= region->size;
930         }
...
948 if (region->read_idx <= region->write_idx) {
949                 w2e = region->size - region->write_idx;
950                 if (count_align <= w2e) {
951                         memcpy(base + region->write_idx, linear_buf, count);
952                         region->write_idx += count_align;
953                         if (region->write_idx == region->size)
954                                 region->write_idx = 0;
 955                 } else {
 956                         memcpy(base + region->write_idx, linear_buf, w2e);
 957                         memcpy(base, (uint8_t *)linear_buf + w2e, count - w2e);
 958                         region->write_idx = count_align - w2e;
 959                 }
```
So all of these checks can be ignored since during the check the variables could be a different value which would later
be changed by another thread. So for example w2e on 949 could become negative and the DMA
region could be overflowed during the memcpy.
Similarly, audio_ipi_dma_read_region calls audio_region_read_to_linear and the checks in that function can be [TOCTOU](https://en.wikipedia.org/wiki/Time-of-check_to_time-of-use)'d.
audio_ipi_dma_read_region uses a buffer passed in from hal_dma_push allocated by  
```
msg_queue->tmp_buf_d2k = vmalloc(MAX_DSP_DMA_WRITE_SIZE);
```
from 
```
1398         retval = audio_ipi_dma_read_region(
1399                          p_ipi_msg->task_scene,
1400                          msg_queue->tmp_buf_d2k,
1401                          p_ipi_msg->dma_info.data_size,
1402                          p_ipi_msg->dma_info.rw_idx);
```

So with these bugs we can read overflow to get a leak for KASLR and write overflow to corrupt some structures in memory and get code execution(see last blog post or someone elses for how to arb write or ROP)
I did not write any exploit just a [PoC](https://github.com/docfate111/testing_android_driver/blob/c1c65936def5168b4b59f53240581ee91eeb1c36/src/test.c) to cause a crash but
the hardest part would be to increase the race window in between functions.

# Reporting

It is a duplicate someone else already found and reported but for some reason never publicly reported.
```
MediaTek Security Team believes that this is a duplicate of an issue previously reported by another external researcher.
The original issue was tracked by: ALPS06478101

Thank you. Where can I find the issue/report? 

We are unable to share the original report.
Apologize for this!
```
I also reported to Samsung but they only consider Samsung specific vulnerabilities not covered by AOSP common issues or chipset vendors.

# Random takeaways

It was cool to learn about gen_pool allocations and how they can do allocations and deallocations concurrently. As a result, the race condition has to be in between uses of freeing and allocating rather than within the function
gen_pool_free and gen_pool_alloc. It has some checks to prevent freeing a different size than what was allocated.

Apparently Android phones use old kernel versions so that old drivers aren't broken. Since these old versions don't support mitigations,
they are implemented by code from Knox.
In this old version there was an [integer overflow](https://lore.kernel.org/lkml/20210111130051.675602171@linuxfoundation.org/) in gen_pool_alloc but it user controlled value is uint32_t which is fine to convert to size_t.

If there is anything I got wrong(typos or technical info) or you know how I can get access to the original report please email me.
