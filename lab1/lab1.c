#include <linux/init.h>
#include <linux/version.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/proc_fs.h>
#include <linux/device.h>
#include <linux/types.h>
#include <linux/kdev_t.h>
#include <linux/fs.h>
#include <linux/cdev.h>
#include <linux/slab.h>
#include <linux/uaccess.h>

static dev_t first;
static struct proc_dir_entry* entry;
static struct cdev c_dev;
static struct class *cl;

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Alexander Verbovoy, Malcev Andrei");
MODULE_DESCRIPTION("Lab1 var3");
MODULE_VERSION("0.0.1");

static int sum = 0;
static int sum_count = 0;
static int MAX_SIZE = 1024;

static int* history;

static ssize_t proc_write(struct file* file, const char __user* ubuf, size_t count, loff_t* ppos)
{
	printk(KERN_NOTICE "proc: write()\n");
	return -1;
}

static ssize_t proc_read(struct file* file, char __user* ubuf, size_t count, loff_t* ppos)
{
	printk(KERN_NOTICE "proc: read()");

	char* local_buf = (char*) kmalloc(sizeof(char) * MAX_SIZE, GFP_KERNEL);

	size_t len = 0;
	size_t i = 0;

	for ( i = 0; i < sum_count; i++)
		len += sprintf(local_buf + len, "%d\n", history[i]);

	if (*ppos > 0 || count < len)
	{
		return 0;
	}
	if (copy_to_user(ubuf, local_buf, len) != 0)
	{
		return -EFAULT;
	}
	*ppos = len;

	kfree(local_buf);
	return len;
}

static ssize_t dev_write(struct file *file, const char __user* ubuf, size_t count, loff_t* ppos)
{
	printk(KERN_NOTICE "dev: write()\n");

	char dig[10] = {0};
	int d_count = 0;
	int num = 0;

	char c;
	size_t i;

	for (i = 0; i < count; i++)
	{
		if (copy_from_user(&c, ubuf + i, 1) != 0)
		{
			return -EFAULT;
		}
		else
		{
			if (c >= '0' && c <= '9')
			{
				dig[d_count++] = c;
			}
			else
			{
				if (d_count > 0)
				{
					kstrtoint(dig, 10, &num);
					memset(dig, 0, 10);
					d_count = 0;

					sum += num;
				}
			}
		}

	} //for



	history[sum_count++] = sum;

	printk(KERN_NOTICE "dev: sum = %d\n", sum);
	return count;
}

static ssize_t dev_read(struct file* file, char __user* ubuf, size_t count, loff_t* ppos)
{
	printk(KERN_NOTICE "dev: read()\n");

	size_t len = strlen(THIS_MODULE->name);
 
	char* local_buf = (char*) kmalloc(sizeof(char) * MAX_SIZE, GFP_KERNEL);
 
	size_t llen = 0;
	size_t i = 0;
 
	for (i = 0; i < sum_count; i++)
		llen += sprintf(local_buf + llen,"%d\n", history[i]);

	printk(KERN_NOTICE "%s", local_buf);
 
	if (*ppos > 0 || count < len)
	{
		return 0;
	}
	if (copy_to_user(ubuf, THIS_MODULE->name, len) != 0) // todo change this 
	{
		return -EFAULT;
	}
	*ppos += len;

	kfree(local_buf);
	return len;
}
static int dev_open(struct inode *i, struct file *f)
{
	printk(KERN_NOTICE "dev: open()\n");
	return 0;
}

static int dev_close(struct inode *i, struct file *f)
{
	printk(KERN_NOTICE "dev: close()\n");
	return 0;
}

static struct file_operations char_dev_fops =
{
	.owner = THIS_MODULE,
	.open = dev_open,
	.release = dev_close,
	.read = dev_read,
	.write = dev_write
};

static struct file_operations fops =
{
	.owner = THIS_MODULE,
	.read = proc_read,
	.write = proc_write
};

// chmod 666 for /dev/var3
static char* set_devnode(struct device* dev, umode_t* mode)
{
	if (mode != NULL)
		*mode = 0666;
	return NULL;
}

static int __init lab1_init(void) {
	history = (int*) kmalloc(sizeof(int) * MAX_SIZE, GFP_KERNEL);

	entry = proc_create("var3", 0444, NULL, &fops);

	if (alloc_chrdev_region(&first, 0, 1, "ch_dev") < 0)
	{
		return -1;
	}
	if ((cl = class_create(THIS_MODULE, "chardrv")) == NULL)
	{
		unregister_chrdev_region(first, 1);
		return -1;
	}

	cl->devnode = set_devnode;

	if (device_create(cl, NULL, first, NULL, "var3") == NULL)
	{
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}
	cdev_init(&c_dev, &char_dev_fops);
	if (cdev_add(&c_dev, first, 1) == -1)
	{
		device_destroy(cl, first);
		class_destroy(cl);
		unregister_chrdev_region(first, 1);
		return -1;
	}
	printk(KERN_NOTICE "Hey, laba\n");
	return 0;
}

static void __exit lab1_exit(void) {
	cdev_del(&c_dev);
	device_destroy(cl, first);
	class_destroy(cl);
	unregister_chrdev_region(first, 1);
	proc_remove(entry);
	printk(KERN_NOTICE "Bye, laba\n");
}

module_init(lab1_init);
module_exit(lab1_exit);