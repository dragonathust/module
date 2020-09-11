/*
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/io.h>
#include <linux/kmsg_dump.h>

MODULE_AUTHOR("xiaolong yi");
MODULE_DESCRIPTION("kernel module used to write dump kmsg to memory");
MODULE_LICENSE("GPL");

static unsigned int physaddr = 0;
static unsigned int memsize = 0;
static void *membuf = NULL;
static int offset = 0;
static struct kmsg_dumper kdump;

module_param(physaddr, uint, S_IRUGO);
module_param(memsize, uint, S_IRUGO);

static 	void  write_msg(const char *buf, int count)
{
	if( offset < memsize ) {
		if( count >0 )
		{
		if( count < memsize-offset ) {
		memcpy(membuf+offset,buf,count);
		offset += count;
		}
		else
		{
		memcpy(membuf+offset,buf,memsize-offset);
		offset += memsize-offset;		
		}
		}
	}
}

static void do_dump(struct kmsg_dumper *dumper, enum kmsg_dump_reason reason,
			const char *s1, unsigned long l1,
			const char *s2, unsigned long l2)
{
	write_msg(s2,l2);

	if(l1)	
	write_msg(s1,l1);	
}

static inline void *console_ioremap(phys_addr_t phys_addr, ssize_t size)
{
	void *retval;

	retval = request_mem_region_exclusive(phys_addr, size, "kmsgdump");
	if (!retval)
		goto fail;

	retval = ioremap_nocache(phys_addr, size);

fail:
	return retval;
}

static int __init init_kmsgdump(void)
{
	int err = 0;

	printk(KERN_INFO "kmsgdump: physaddr=0x%08x,memsize=0x%08x\n",physaddr,memsize);

	if((!physaddr)||(!memsize))
	return -EINVAL;
	
	membuf = console_ioremap(physaddr,memsize);
	if(!membuf)
	{
	printk(KERN_ERR "kmsgdump: ioremap failed\n");
	return -EINVAL;	
	}
	
	memset(membuf,0,memsize);
	memset(&kdump,0,sizeof(struct kmsg_dumper));
	kdump.dump = do_dump;
	err = kmsg_dump_register(&kdump);
	
	printk(KERN_INFO "kmsgdump: kmsg dump registered,err=%d\n",err);

	return err;
}

static void __exit cleanup_kmsgdump(void)
{
	if(membuf)
	{
	iounmap(membuf);
	membuf =  NULL;
	}
	release_mem_region(physaddr, memsize);
	kmsg_dump_unregister(&kdump);
	
	printk(KERN_INFO "kmsgdump: kmsg dump unregistered\n");	
}

module_init(init_kmsgdump);
module_exit(cleanup_kmsgdump);
