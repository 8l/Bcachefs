/*
 * This file adds support for a character device /dev/bcache that is used to
 * atomically register a list of devices, remove a device from a cache_set
 * and add a device to a cache set.
 *
 * Copyright (c) 2014 Datera, Inc.
 *
 */

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bcache-ioctl.h>
#include "bcache.h"


#define MAX_ARG_STRINGS MAX_CACHES_PER_SET
#define MAX_PATH	256

static struct class *bch_chardev_class;
static int bch_chardev_major;
static struct device *bch_chardev;

static int count_args(const char __user *const __user *argv, int max)
{
	int i = 0, len = 0;

	if (argv != NULL) {
		for (i = 0;; i++) {
			const char __user *str;

			get_user(str, argv + i);
			if (!str)
				break;

			if (i >= max)
				return -E2BIG;

			len = strnlen_user(str, MAX_PATH);
			if (!len)
				return -E2BIG;
		}
	}
	return i;
}

static int copy_array_from_user(const char __user *const __user *argv,
				char *path[], int count)
{
	int len = 0, i = 0, ret = 0;

	if (argv != NULL) {
		for (i = 0; i < count; i++) {
			const char __user *str;
			char *kstr;

			if (get_user(str, argv + i)) {
				ret = -EFAULT;
				break;
			}

			if (!str) {
				ret = -EFAULT;
				break;
			}

			if (IS_ERR(str)) {
				ret = -EFAULT;
				break;
			}

			len = strnlen_user(str, MAX_PATH);

			kstr = kmalloc(GFP_KERNEL, len);
			if (!kstr) {
				ret = -ENOMEM;
				break;
			}
			if (copy_from_user(kstr, str, len)) {
				ret = -EFAULT;
				break;
			}
			path[i] = kstr;
		}
	}
	if (ret) {
		for (count = count-1; count > 0; count--)
			kfree(path[count]);
	}
	return ret;
}

static long bch_ioctl_register(const char __user *const __user *argv)
{

	int count, ret, i;
	char **path = NULL;
	const char *err;
	struct cache_set *c = NULL;

	if (!try_module_get(THIS_MODULE))
		return -EBUSY;
	count = count_args(argv, MAX_ARG_STRINGS);
	if (count <= 0)
		goto err;

	path = kmalloc(GFP_KERNEL, (sizeof(char *)) * (count + 1));
	if (!path) {
		pr_err("Could not allocate memory to path");
		goto err;
	}

	ret = copy_array_from_user(argv, path, count);
	if (ret) {
		pr_err("copy_array_from_user returned %d", ret);
		goto err;
	}

	path[count] = NULL;

	err = register_bcache_devices(path, count, &c);
	if (!err)
		err = bch_run_cache_set(c);
	if (err) {
		pr_err("Could not register bcache devices: %s", err);
		ret = -EINVAL;
	}
	for (i = 0; i < count; i++)
		kfree(path[i]);
err:
	kfree(path);
	module_put(THIS_MODULE);
	return ret;
}

static long bch_chardev_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	const char __user *const __user *path =
				(void __user *)arg;

	switch (cmd) {
	case BCH_IOCTL_REGISTER:
		return bch_ioctl_register(path);
	case BCH_IOCTL_ADD_DISK:
	case BCH_IOCTL_RM_DISK:
	default:
		return -ENOTTY;
	}
	return 0;
}

static const struct file_operations bch_chardev_fops = {
	.open		=	nonseekable_open,
	.unlocked_ioctl =	bch_chardev_ioctl,
	.owner		=	THIS_MODULE,
};

int __init bch_chardev_init(void)
{
	int ret = 0;
	bch_chardev_major = register_chrdev(0, "bcache", &bch_chardev_fops);
	if (bch_chardev_major < 0)
		goto err;

	bch_chardev_class = class_create(THIS_MODULE, "bcache");
	if (IS_ERR(bch_chardev_class)) {
		pr_err("Error creating a bcache class");
		ret = PTR_ERR(bch_chardev_class);
		goto err;
	}
	bch_chardev = device_create(bch_chardev_class, NULL,
				MKDEV(bch_chardev_major, 0), NULL, "bcache");
	if (IS_ERR(bch_chardev)) {
		pr_err("Error creating a bcache char device");
		ret = PTR_ERR(bch_chardev);
		goto err;
	}
	return ret;
err:
	bch_chardev_exit();
	return ret;
}

void __exit bch_chardev_exit(void)
{
	if (bch_chardev_major) {
		if (bch_chardev_class && bch_chardev)
			device_destroy(bch_chardev_class,
				       MKDEV(bch_chardev_major, 0));
		if (bch_chardev_class)
			class_destroy(bch_chardev_class);
		unregister_chrdev(bch_chardev_major, "bcache");
	}
}

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("character device that manages bcache device life cycle");
