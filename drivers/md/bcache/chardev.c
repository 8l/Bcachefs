/*
 * This file adds support for a character device /dev/bcache that is used to
 * atomically register a list of devices, remove a device from a cache_set
 * and add a device to a cache set.
 *
 * Copyright (c) 2014 Datera, Inc.
 *
 */

#include "bcache.h"
#include "super.h"

#include <linux/module.h>
#include <linux/fs.h>
#include <linux/major.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/ioctl.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/bcache-ioctl.h>

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

			kstr = kmalloc(len, GFP_KERNEL);
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

static int ioctl_init(const char __user *const __user *argv,
		char **path[], int *countret)
{
	int ret = 0, count = 0;

	count = count_args(argv, MAX_ARG_STRINGS);
	if (count <= 0)
		return -EINVAL;

	*path = kzalloc((sizeof(char *)) * (count + 1), GFP_KERNEL);
	if (!*path) {
		pr_err("Could not allocate memory to path");
		return -ENOMEM;
	}

	ret = copy_array_from_user(argv, *path, count);
	if (ret) {
		pr_err("copy_array_from_user returned %d", ret);
		return ret;
	}

	(*path)[count] = NULL;
	*countret = count;

	return 0;
}

static long bch_ioctl_register(const char __user *const __user *argv)
{
	int ret = 0, i = 0, count = 0;
	const char *err;
	char **path = NULL;
	struct cache_set *c = NULL;

	ret = ioctl_init(argv, &path, &count);
	if (ret) {
		pr_err("Unable to initialize register ioctl, "
				"returned with %d", ret);
		goto err;
	}

	err = register_bcache_devices(path, count, &c);
	if (err) {
		pr_err("Could not register bcache devices: %s", err);
		ret = -EINVAL;
		goto err;
	}

	if (c) {
		mutex_lock(&bch_register_lock);
		err = bch_run_cache_set(c);
		mutex_unlock(&bch_register_lock);
		if (err) {
			pr_err("Could not run cacheset: %s", err);
			ret = -EINVAL;
			goto err;
		}
	}

err:
	for (i = 0; i < count; i++)
		kfree(path[i]);
	kfree(path);
	return ret;
}

static long bch_ioctl_cache_set_stop(struct cache_set *c)
{
	bch_cache_set_stop(c);
	return 0;
}

static long bch_ioctl_add_devs(struct cache_set *c,
		struct bch_ioctl_add_disks *arg)
{
	int ret = 0, i = 0, count = 0;
	char **path = NULL;
	struct bch_ioctl_add_disks ia;

	if (copy_from_user(&ia, arg, sizeof(struct bch_ioctl_add_disks)))
		return -EFAULT;

	ret = ioctl_init((const char __user *const __user *)ia.devs,
			&path, &count);
	if (ret) {
		pr_err("Unable to initialize add_devs ioctl, "
				"returned with %d", ret);
		goto err;
	}

	for (i = 0; i < count; i++) {
		ret = bch_cache_set_add_cache(c, path[i]);
		if(ret)
			goto err;
	}

err:
	for (i = 0; i < count; i++)
		kfree(path[i]);
	kfree(path);

	return ret;
}

static long bch_ioctl_rm_dev(struct cache_set *c,
		struct bch_ioctl_rm_disk *arg)
{
	int ret = 0, len = 0;
	char *kstr = NULL;
	const char *err;
	struct bch_ioctl_rm_disk ir;

	if (copy_from_user(&ir, arg, sizeof(struct bch_ioctl_rm_disk)))
		return -EFAULT;

	len = strnlen_user(ir.dev, MAX_PATH);

	kstr = kmalloc(len, GFP_KERNEL);
	if (!kstr) {
		ret = -ENOMEM;
		goto err;
	}

	if (copy_from_user(kstr, ir.dev, len)) {
		ret = -EFAULT;
		goto err;
	}

	err = remove_bcache_device(kstr, ir.force, c);
	if (err) {
		ret = -EINVAL;
		pr_err("Unable to remove bcache device: %s", err);
	}

err:
	kfree(kstr);

	return ret;
}

static long bch_ioctl_disk_failed(struct cache_set *c,
		struct bch_ioctl_disk_failed *arg)
{
	int ret = 0;
	const char *err;
	struct bch_ioctl_disk_failed df;

	if (copy_from_user(&df, arg, sizeof(struct bch_ioctl_disk_failed)))
		return -EFAULT;

	err = set_disk_failed(df.dev_uuid, c);
	if (err) {
		ret = -EINVAL;
		pr_err("Unable to set bcache device %s to failed", err);
	}

	return ret;
}

/* These ioctls are accessed through /dev/bcache */
static long bch_chardev_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	const char __user *const __user *path;

	switch (cmd) {
	case BCH_IOCTL_REGISTER:
		path = (void __user *)arg;
		return bch_ioctl_register(path);

	default:
		return -ENOSYS;
	}
}

/*
 * These ioctls are given the struct cache_set through the
 * /dev/bcache_extent0 chardev
 */
long bch_cacheset_ioctl(struct cache_set *c, unsigned int cmd,
		unsigned long arg)
{
	switch (cmd) {
	case BCH_IOCTL_STOP:
		return bch_ioctl_cache_set_stop(c);
	case BCH_IOCTL_ADD_DISKS:
		return bch_ioctl_add_devs(c,
			(struct bch_ioctl_add_disks *) arg);
	case BCH_IOCTL_RM_DISK:
		return bch_ioctl_rm_dev(c,
			(struct bch_ioctl_rm_disk *)arg);
	case BCH_IOCTL_SET_DISK_FAILED:
		return bch_ioctl_disk_failed(c,
			(struct bch_ioctl_disk_failed *)arg);

	default:
		return -ENOSYS;
	}
}

static const struct file_operations bch_chardev_fops = {
	.open		=	nonseekable_open,
	.unlocked_ioctl =	bch_chardev_ioctl,
	.owner		=	THIS_MODULE,
};

void bch_chardev_exit(void)
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

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("character device that manages bcache device life cycle");
