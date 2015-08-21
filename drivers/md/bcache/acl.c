#include "bcache.h"

#include <linux/init.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/fs.h>

#include "xattr.h"
#include "acl.h"

/*
 * Convert from filesystem to in-memory representation.
 */
static struct posix_acl *bch_acl_from_disk(const void *value, size_t size)
{
	const char *end = (char *)value + size;
	int n, count;
	struct posix_acl *acl;

	if (!value)
		return NULL;
	if (size < sizeof(bch_acl_header))
		return ERR_PTR(-EINVAL);
	if (((bch_acl_header *)value)->a_version !=
	    cpu_to_le32(BCH_ACL_VERSION))
		return ERR_PTR(-EINVAL);
	value = (char *)value + sizeof(bch_acl_header);
	count = bch_acl_count(size);
	if (count < 0)
		return ERR_PTR(-EINVAL);
	if (count == 0)
		return NULL;
	acl = posix_acl_alloc(count, GFP_KERNEL);
	if (!acl)
		return ERR_PTR(-ENOMEM);
	for (n = 0; n < count; n++) {
		bch_acl_entry *entry =
			(bch_acl_entry *)value;
		if ((char *)value + sizeof(bch_acl_entry_short) > end)
			goto fail;
		acl->a_entries[n].e_tag  = le16_to_cpu(entry->e_tag);
		acl->a_entries[n].e_perm = le16_to_cpu(entry->e_perm);
		switch (acl->a_entries[n].e_tag) {
		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			value = (char *)value +
				sizeof(bch_acl_entry_short);
			break;

		case ACL_USER:
			value = (char *)value + sizeof(bch_acl_entry);
			if ((char *)value > end)
				goto fail;
			acl->a_entries[n].e_uid =
				make_kuid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;
		case ACL_GROUP:
			value = (char *)value + sizeof(bch_acl_entry);
			if ((char *)value > end)
				goto fail;
			acl->a_entries[n].e_gid =
				make_kgid(&init_user_ns,
					  le32_to_cpu(entry->e_id));
			break;

		default:
			goto fail;
		}
	}
	if (value != end)
		goto fail;
	return acl;

fail:
	posix_acl_release(acl);
	return ERR_PTR(-EINVAL);
}

/*
 * Convert from in-memory to filesystem representation.
 */
static void *bch_acl_to_disk(const struct posix_acl *acl, size_t *size)
{
	bch_acl_header *ext_acl;
	char *e;
	size_t n;

	*size = bch_acl_size(acl->a_count);
	ext_acl = kmalloc(sizeof(bch_acl_header) + acl->a_count *
			sizeof(bch_acl_entry), GFP_KERNEL);
	if (!ext_acl)
		return ERR_PTR(-ENOMEM);
	ext_acl->a_version = cpu_to_le32(BCH_ACL_VERSION);
	e = (char *)ext_acl + sizeof(bch_acl_header);
	for (n = 0; n < acl->a_count; n++) {
		const struct posix_acl_entry *acl_e = &acl->a_entries[n];
		bch_acl_entry *entry = (bch_acl_entry *)e;

		entry->e_tag = cpu_to_le16(acl_e->e_tag);
		entry->e_perm = cpu_to_le16(acl_e->e_perm);
		switch (acl_e->e_tag) {
		case ACL_USER:
			entry->e_id = cpu_to_le32(
				from_kuid(&init_user_ns, acl_e->e_uid));
			e += sizeof(bch_acl_entry);
			break;
		case ACL_GROUP:
			entry->e_id = cpu_to_le32(
				from_kgid(&init_user_ns, acl_e->e_gid));
			e += sizeof(bch_acl_entry);
			break;

		case ACL_USER_OBJ:
		case ACL_GROUP_OBJ:
		case ACL_MASK:
		case ACL_OTHER:
			e += sizeof(bch_acl_entry_short);
			break;

		default:
			goto fail;
		}
	}
	return (char *)ext_acl;

fail:
	kfree(ext_acl);
	return ERR_PTR(-EINVAL);
}

struct posix_acl *bch_get_acl(struct inode *inode, int type)
{
	struct cache_set *c = inode->i_sb->s_fs_info;
	int name_index;
	char *value = NULL;
	struct posix_acl *acl;
	int ret;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = BCH_XATTR_INDEX_POSIX_ACL_ACCESS;
		break;
	case ACL_TYPE_DEFAULT:
		name_index = BCH_XATTR_INDEX_POSIX_ACL_DEFAULT;
		break;
	default:
		BUG();
	}
	ret = bch_xattr_get(c, inode->i_ino, "", NULL, 0, name_index);
	if (ret > 0) {
		value = kmalloc(ret, GFP_KERNEL);
		if (!value)
			return ERR_PTR(-ENOMEM);
		ret = bch_xattr_get(c, inode->i_ino, "", value,
				    ret, name_index);
	}
	if (ret > 0)
		acl = bch_acl_from_disk(value, ret);
	else if (ret == -ENODATA || ret == -ENOSYS)
		acl = NULL;
	else
		acl = ERR_PTR(ret);
	kfree(value);

	if (!IS_ERR(acl))
		set_cached_acl(inode, type, acl);

	return acl;
}

int bch_set_acl(struct inode *inode, struct posix_acl *acl, int type)
{
	int name_index;
	void *value = NULL;
	size_t size = 0;
	int ret;

	switch (type) {
	case ACL_TYPE_ACCESS:
		name_index = BCH_XATTR_INDEX_POSIX_ACL_ACCESS;
		if (acl) {
			ret = posix_acl_equiv_mode(acl, &inode->i_mode);
			if (ret < 0)
				return ret;
			else {
				inode->i_ctime = CURRENT_TIME_SEC;
				mark_inode_dirty(inode);
				if (ret == 0)
					acl = NULL;
			}
		}
		break;

	case ACL_TYPE_DEFAULT:
		name_index = BCH_XATTR_INDEX_POSIX_ACL_DEFAULT;
		if (!S_ISDIR(inode->i_mode))
			return acl ? -EACCES : 0;
		break;

	default:
		return -EINVAL;
	}

	if (acl) {
		value = bch_acl_to_disk(acl, &size);
		if (IS_ERR(value))
			return (int)PTR_ERR(value);
	}

	ret = bch_xattr_set(inode, "", value, size, 0, name_index);

	kfree(value);

	if (ret == -ERANGE)
		ret = -E2BIG;

	if (!ret)
		set_cached_acl(inode, type, acl);

	return ret;
}

int bch_init_acl(struct inode *inode, struct inode *dir)
{
	struct posix_acl *default_acl, *acl;
	int ret;

	ret = posix_acl_create(dir, &inode->i_mode, &default_acl, &acl);
	if (ret)
		return ret;

	if (default_acl) {
		ret = bch_set_acl(inode, default_acl, ACL_TYPE_DEFAULT);
		posix_acl_release(default_acl);
	}
	if (acl) {
		if (!ret)
			ret = bch_set_acl(inode, acl, ACL_TYPE_ACCESS);
		posix_acl_release(acl);
	}
	return ret;
}
