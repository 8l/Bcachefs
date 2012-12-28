#ifndef _BCACHE_SYSFS_H_
#define _BCACHE_SYSFS_H_

#define KTYPE(type, _release)						\
static const struct sysfs_ops type ## _ops = {				\
	.show		= type ## _show,				\
	.store		= type ## _store				\
};									\
static struct kobj_type type ## _obj = {				\
	.release	= _release,					\
	.sysfs_ops	= &type ## _ops,				\
	.default_attrs	= type ## _files				\
}

#define SHOW(fn)							\
static ssize_t fn ## _show(struct kobject *kobj, struct attribute *attr,\
			   char *buf)					\

#define STORE(fn)							\
static ssize_t fn ## _store(struct kobject *kobj, struct attribute *attr,\
			    const char *buf, size_t size)		\

#define SHOW_LOCKED(fn)							\
SHOW(fn)								\
{									\
	ssize_t ret;							\
	mutex_lock(&register_lock);					\
	ret = __ ## fn ## _show(kobj, attr, buf);			\
	mutex_unlock(&register_lock);					\
	return ret;							\
}

#define STORE_LOCKED(fn)						\
STORE(fn)								\
{									\
	ssize_t ret;							\
	mutex_lock(&register_lock);					\
	ret = __ ## fn ## _store(kobj, attr, buf, size);		\
	mutex_unlock(&register_lock);					\
	return ret;							\
}

#define __sysfs_attribute(_name, _mode)					\
	static struct attribute sysfs_##_name =				\
		{ .name = #_name, .mode = _mode }

#define write_attribute(n)	__sysfs_attribute(n, S_IWUSR)
#define read_attribute(n)	__sysfs_attribute(n, S_IRUGO)
#define rw_attribute(n)		__sysfs_attribute(n, S_IRUGO|S_IWUSR)

#define sysfs_printf(file, fmt, ...)					\
	if (attr == &sysfs_ ## file)					\
		return snprintf(buf, PAGE_SIZE, fmt "\n", __VA_ARGS__)

#define sysfs_print(file, var)						\
	if (attr == &sysfs_ ## file)					\
		return snprint(buf, PAGE_SIZE, var)

#define sysfs_hprint(file, val)						\
	if (attr == &sysfs_ ## file) {					\
		ssize_t ret = hprint(buf, val);				\
		strcat(buf, "\n");					\
		return ret + 1;						\
	}

#define var_printf(_var, fmt)	sysfs_printf(_var, fmt, var(_var))
#define var_print(_var)		sysfs_print(_var, var(_var))
#define var_hprint(_var)	sysfs_hprint(_var, var(_var))

#define sysfs_strtoul(file, var)					\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe(buf, var) ?: (ssize_t) size;

#define sysfs_strtoul_clamp(file, var, min, max)			\
	if (attr == &sysfs_ ## file)					\
		return strtoul_safe_clamp(buf, var, min, max)		\
			?: (ssize_t) size;

#define strtoul_or_return(cp)						\
({									\
	unsigned long _v;						\
	int _r = strict_strtoul(cp, 10, &_v);				\
	if (_r)								\
		return _r;						\
	_v;								\
})

#define strtoi_h_or_return(cp, v)					\
do {									\
	int _r = strtoi_h(cp, &v);					\
	if (_r)								\
		return _r;						\
} while (0)

#define sysfs_hatoi(file, var)						\
	if (attr == &sysfs_ ## file)					\
		return strtoi_h(buf, &var) ?: (ssize_t) size;

#endif  /* _BCACHE_SYSFS_H_ */
