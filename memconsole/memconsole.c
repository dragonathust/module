/*
 */

#include <linux/mm.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/console.h>
#include <linux/moduleparam.h>
#include <linux/string.h>
#include <linux/netpoll.h>
#include <linux/inet.h>
#include <linux/configfs.h>

MODULE_AUTHOR("xiaolong yi");
MODULE_DESCRIPTION("kernel module used to write console to memory");
MODULE_LICENSE("GPL");

static unsigned int physaddr = 0;
static unsigned int memsize = 0;
static void *membuf = NULL;
static int offset = 0;

module_param(physaddr, uint, S_IRUGO);
module_param(memsize, uint, S_IRUGO);

static void write_msg(struct console *con, const char *msg, unsigned int len)
{
	if( offset < memsize ) {
		snprintf(membuf+offset,memsize-offset,"%s",msg);
		offset += strlen(msg);
	}
}

static struct console memconsole = {
	.name	= "memcon",
	.flags	= CON_ENABLED,
	.write	= write_msg,
};

static inline void *console_ioremap(phys_addr_t phys_addr, ssize_t size)
{
	void *retval;

	retval = request_mem_region_exclusive(phys_addr, size, "memcon");
	if (!retval)
		goto fail;

	retval = ioremap_nocache(phys_addr, size);

fail:
	return retval;
}

static int __init init_memconsole(void)
{
	int err = 0;

	printk(KERN_INFO "memconsole: physaddr=0x%08x,memsize=0x%08x\n",physaddr,memsize);

	if((!physaddr)||(!memsize))
	return -EINVAL;
	
	membuf = console_ioremap(physaddr,memsize);
	if(!membuf)
	{
	printk(KERN_ERR "memconsole: ioremap failed\n");
	return -EINVAL;	
	}
	
	memset(membuf,0,memsize);
	
	/* Dump existing printks when we register */
	memconsole.flags |= CON_PRINTBUFFER;

	register_console(&memconsole);
	printk(KERN_INFO "memconsole: memory logging started\n");

	return err;
}

static void __exit cleanup_memconsole(void)
{
	if(membuf)
	{
	iounmap(membuf);
	membuf =  NULL;
	}
	release_mem_region(physaddr, memsize);
	unregister_console(&memconsole);

	printk(KERN_INFO "memconsole: memory logging stoped\n");	
}

module_init(init_memconsole);
module_exit(cleanup_memconsole);
