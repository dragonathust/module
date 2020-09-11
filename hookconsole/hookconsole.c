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
#include <linux/tty.h>
#include <linux/tty_driver.h>

MODULE_AUTHOR("xiaolong yi");
MODULE_DESCRIPTION("kernel module used to hook a write function to the tty");
MODULE_LICENSE("GPL");

typedef	int  (*write_fn)(struct tty_struct * tty,
		      const unsigned char *buf, int count);

static unsigned int physaddr = 0;
static unsigned int memsize = 0;
static void *membuf = NULL;
static int offset = 0;

const struct tty_operations *tty_ops_base = NULL;
static struct tty_operations *tty_ops_new = NULL;

static struct mutex replace_lock;
static spinlock_t lock;

	
module_param(physaddr, uint, S_IRUGO);
module_param(memsize, uint, S_IRUGO);


static 	int  write_msg(struct tty_struct * tty,
		      const unsigned char *buf, int count)
{
int ret=0;

	mutex_lock(&replace_lock);

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
	
	if(tty_ops_base)
	ret = tty_ops_base->write(tty,buf,count);
		
	mutex_unlock(&replace_lock);

return ret;	
}


static inline void *console_ioremap(phys_addr_t phys_addr, ssize_t size)
{
	void *retval;

	retval = request_mem_region_exclusive(phys_addr, size, "hookcon");
	if (!retval)
		goto fail;

	retval = ioremap_nocache(phys_addr, size);

fail:
	return retval;
}


static int hook_write_console(write_fn pwrite)
{
	unsigned long		flags;
		
	struct tty_struct *tty = get_current_tty();
	
	if( tty->driver && tty->driver->ops )
	{
		printk(KERN_INFO "hook: tty->driver->name[%s],tty->index=[%d]\n",tty->driver->name,tty->index);
		printk(KERN_INFO "hook: tty->driver->driver_name[%s]\n",tty->driver->driver_name);
		printk(KERN_INFO "hook: major[%d],minor_start[%d],minor_num[%d],num[%d]\n",tty->driver->major,
							tty->driver->minor_start,tty->driver->minor_num,tty->driver->num);
		
		tty_ops_new = kmalloc(sizeof(struct tty_operations),GFP_KERNEL);
		if(!tty_ops_new)
			return -ENOMEM;
			
		tty_unregister_device(tty->driver,tty->index);
		
			spin_lock_irqsave(&lock, flags);
			tty_ops_base = tty->driver->ops;
			memcpy(tty_ops_new,tty_ops_base,sizeof(struct tty_operations));
			tty_ops_new->write = pwrite;
			tty->driver->ops = tty_ops_new;
			tty->ops = tty->driver->ops;
			spin_unlock_irqrestore(&lock, flags);	
			
		tty_register_device(tty->driver,tty->index,NULL);	
	}
	return 0;
}


static void unhook_write_console(void)
{
	struct tty_struct *tty = get_current_tty();

	if( tty->driver && tty->driver->ops )
	{
		printk(KERN_INFO "unhook: tty->driver->name[%s],tty->index=[%d]\n",tty->driver->name,tty->index);
		printk(KERN_INFO "unhook: tty->driver->driver_name[%s]\n",tty->driver->driver_name);

		mutex_lock(&replace_lock);
		tty_unregister_device(tty->driver,tty->index);
					
			tty->driver->ops = tty_ops_base;
			tty->ops = tty->driver->ops;			
			if(tty_ops_new)
			{
				kfree(tty_ops_new);
				tty_ops_new = NULL;
			}
			
		tty_register_device(tty->driver,tty->index,NULL);
		mutex_unlock(&replace_lock);
	}
}


static int __init init_hookconsole(void)
{
	int err = 0;

	printk(KERN_INFO "hookconsole: physaddr=0x%08x,memsize=0x%08x\n",physaddr,memsize);

	if((!physaddr)||(!memsize))
	return -EINVAL;
	
	membuf = console_ioremap(physaddr,memsize);
	if(!membuf)
	{
	printk(KERN_ERR "hookconsole: ioremap failed\n");
	return -EINVAL;	
	}
	
	memset(membuf,0,memsize);
	
	spin_lock_init(&lock);
	mutex_init(&replace_lock);
	err = hook_write_console(&write_msg);

	printk(KERN_INFO "hookconsole: write function hooked,err=%d\n",err);	
	
	return err;
}

static void __exit cleanup_hookconsole(void)
{
	unhook_write_console();

	if(membuf)
	{
	iounmap(membuf);
	membuf =  NULL;
	}
	release_mem_region(physaddr, memsize);

	printk(KERN_INFO "hookconsole: write function unhooked\n");	
}

module_init(init_hookconsole);
module_exit(cleanup_hookconsole);
