/*
 * lib/dynamic_fault.c
 *
 * make fault() calls runtime configurable based upon their
 * source module.
 *
 * Copyright (C) 2011 Adam Berkan <aberkan@google.com>
 * Based on dynamic_debug.c:
 * Copyright (C) 2008 Jason Baron <jbaron@redhat.com>
 * By Greg Banks <gnb@melbourne.sgi.com>
 * Copyright (c) 2008 Silicon Graphics Inc.  All Rights Reserved.
 *
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/kallsyms.h>
#include <linux/version.h>
#include <linux/types.h>
#include <linux/mutex.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/list.h>
#include <linux/sysctl.h>
#include <linux/ctype.h>
#include <linux/string.h>
#include <linux/uaccess.h>
#include <linux/dynamic_fault.h>
#include <linux/debugfs.h>
#include <linux/slab.h>

extern struct _dfault __start___faults[];
extern struct _dfault __stop___faults[];

/* dynamic_fault_enabled, and dynamic_fault_enabled2 are bitmasks in which
 * bit n is set to 1 if any modname hashes into the bucket n, 0 otherwise. They
 * use independent hash functions, to reduce the chance of false positives.
 */
long long dynamic_fault_enabled;
EXPORT_SYMBOL_GPL(dynamic_fault_enabled);
long long dynamic_fault_enabled2;
EXPORT_SYMBOL_GPL(dynamic_fault_enabled2);

struct dfault_table {
	struct list_head link;
	char *mod_name;
	unsigned int num_dfaults;
	unsigned int num_enabled;
	struct _dfault *dfaults;
};

struct dfault_query {
	const char *filename;
	const char *module;
	const char *function;
	unsigned int first_lineno, last_lineno;
};

struct dfault_iter {
	struct dfault_table *table;
	unsigned int idx;
};

static DEFINE_MUTEX(dfault_lock);
static LIST_HEAD(dfault_tables);
static int verbose;

/* Return the last part of a pathname */
static inline const char *basename(const char *path)
{
	const char *tail = strrchr(path, '/');
	return tail ? tail+1 : path;
}

/* format a string into buf[] which describes the _dfault's flags */
static char *dfault_describe_flags(struct _dfault *df, char *buf,
				    size_t maxlen)
{
	char *p = buf;

	BUG_ON(maxlen < 4);
	if (df->flags & _DFAULT_ON)
		*p++ = 'f';
	if (df->flags & _DFAULT_ONE_SHOT)
		*p++ = 'o';
	if (p == buf)
		*p++ = '-';
	*p = '\0';

	return buf;
}

/*
 * must be called with dfault_lock held
 */

/*
 * Search the tables for _dfault's which match the given
 * `query' and apply the `flags' and `mask' to them.  Tells
 * the user which dfault's were changed, or whether none
 * were matched.
 */
static void dfault_change(const struct dfault_query *query,
			   unsigned int flags, unsigned int mask)
{
	int i;
	struct dfault_table *dt;
	unsigned int newflags;
	unsigned int nfound = 0;
	char flagbuf[8];

	/* search for matching dfaults */
	mutex_lock(&dfault_lock);
	list_for_each_entry(dt, &dfault_tables, link) {

		/* match against the module name */
		if (query->module != NULL &&
		    strcmp(query->module, dt->mod_name))
			continue;

		for (i = 0 ; i < dt->num_dfaults ; i++) {
			struct _dfault *df = &dt->dfaults[i];

			/* match against the source filename */
			if (query->filename != NULL &&
			    strcmp(query->filename, df->filename) &&
			    strcmp(query->filename, basename(df->filename)))
				continue;

			/* match against the function */
			if (query->function != NULL &&
			    strcmp(query->function, df->function))
				continue;

			/* match against the line number range */
			if (query->first_lineno &&
			    df->lineno < query->first_lineno)
				continue;
			if (query->last_lineno &&
			    df->lineno > query->last_lineno)
				continue;

			nfound++;

			newflags = (df->flags & mask) | flags;
			if (newflags == df->flags)
				continue;

			if (!newflags)
				dt->num_enabled--;
			else if (!df->flags)
				dt->num_enabled++;

			df->flags = newflags;
			if (newflags)
				static_key_slow_inc(&df->enabled);

			if (verbose)
				printk(KERN_INFO
					"dfault: changed %s:%d [%s]%s %s\n",
					df->filename, df->lineno,
					dt->mod_name, df->function,
					dfault_describe_flags(df, flagbuf,
							      sizeof(flagbuf)));
		}
	}
	mutex_unlock(&dfault_lock);

	if (!nfound && verbose)
		printk(KERN_INFO "dfault: no matches for query\n");
}

/*
 * Split the buffer `buf' into space-separated words.
 * Handles simple " and ' quoting, i.e. without nested,
 * embedded or escaped \".  Return the number of words
 * or <0 on error.
 */
static int dfault_tokenize(char *buf, char *words[], int maxwords)
{
	int nwords = 0;

	while (*buf) {
		char *end;

		/* Skip leading whitespace */
		buf = skip_spaces(buf);
		if (!*buf)
			break;	/* oh, it was trailing whitespace */

		/* Run `end' over a word, either whitespace separated or quoted
		 */
		if (*buf == '"' || *buf == '\'') {
			int quote = *buf++;
			for (end = buf ; *end && *end != quote ; end++)
				;
			if (!*end)
				return -EINVAL;	/* unclosed quote */
		} else {
			for (end = buf ; *end && !isspace(*end) ; end++)
				;
			BUG_ON(end == buf);
		}
		/* Here `buf' is the start of the word, `end' is one past the
		 * end
		 */

		if (nwords == maxwords)
			return -EINVAL;	/* ran out of words[] before bytes */
		if (*end)
			*end++ = '\0';	/* terminate the word */
		words[nwords++] = buf;
		buf = end;
	}

	if (verbose) {
		int i;
		printk(KERN_INFO "%s: split into words:", __func__);
		for (i = 0 ; i < nwords ; i++)
			printk(" \"%s\"", words[i]);
		printk("\n");
	}

	return nwords;
}

/*
 * Parse a single line number.  Note that the empty string ""
 * is treated as a special case and converted to zero, which
 * is later treated as a "don't care" value.
 */
static inline int parse_lineno(const char *str, unsigned int *val)
{
	char *end = NULL;
	BUG_ON(str == NULL);
	if (*str == '\0') {
		*val = 0;
		return 0;
	}
	*val = simple_strtoul(str, &end, 10);
	return end == NULL || end == str || *end != '\0' ? -EINVAL : 0;
}

/*
 * Parse words[] as a dfault query specification, which is a series
 * of (keyword, value) pairs chosen from these possibilities:
 *
 * func <function-name>
 * file <full-pathname>
 * file <base-filename>
 * module <module-name>
 * line <lineno>
 * line <first-lineno>-<last-lineno> // where either may be empty
 */
static int dfault_parse_query(char *words[], int nwords,
			      struct dfault_query *query)
{
	unsigned int i;

	/* check we have an even number of words */
	if (nwords % 2 != 0)
		return -EINVAL;
	memset(query, 0, sizeof(*query));

	for (i = 0 ; i < nwords ; i += 2) {
		if (!strcmp(words[i], "func"))
			query->function = words[i+1];
		else if (!strcmp(words[i], "file"))
			query->filename = words[i+1];
		else if (!strcmp(words[i], "module"))
			query->module = words[i+1];
		else if (!strcmp(words[i], "line")) {
			char *first = words[i+1];
			char *last = strchr(first, '-');
			if (last)
				*last++ = '\0';
			if (parse_lineno(first, &query->first_lineno) < 0)
				return -EINVAL;
			if (last != NULL) {
				/* range <first>-<last> */
				if (parse_lineno(last, &query->last_lineno) < 0)
					return -EINVAL;
			} else {
				query->last_lineno = query->first_lineno;
			}
		} else {
			if (verbose)
				printk(KERN_ERR "%s: unknown keyword \"%s\"\n",
					__func__, words[i]);
			return -EINVAL;
		}
	}

	if (verbose)
		printk(KERN_INFO "%s: q->function=\"%s\" q->filename=\"%s\" "
		       "q->module=\"%s\" q->lineno=%u-%u\n",
			__func__, query->function, query->filename,
			query->module, query->first_lineno,
			query->last_lineno);

	return 0;
}

/*
 * Parse `str' as a flags specification, format [-+=][p]+.
 * Sets up *maskp and *flagsp to be used when changing the
 * flags fields of matched _dfault's.  Returns 0 on success
 * or <0 on error.
 */
static int dfault_parse_flags(const char *str, unsigned int *flagsp,
			       unsigned int *maskp)
{
	unsigned flags = 0;
	int op = '=';

	switch (*str) {
	case '+':
	case '-':
	case '=':
		op = *str++;
		break;
	default:
		return -EINVAL;
	}
	if (verbose)
		printk(KERN_INFO "%s: op='%c', flag='%c'\n", __func__,
		       op, *str);

	for ( ; *str ; ++str) {
		switch (*str) {
		case 'f':
			flags |= _DFAULT_ON;
			break;
		case 'o':
			flags |= _DFAULT_ONE_SHOT;
			break;
		default:
			return -EINVAL;
		}
	}
	if (flags == 0)
		return -EINVAL;
	if (verbose)
		printk(KERN_INFO "%s: flags=0x%x\n", __func__, flags);

	/* calculate final *flagsp, *maskp according to mask and op */
	switch (op) {
	case '=':
		*maskp = 0;
		*flagsp = flags;
		break;
	case '+':
		*maskp = ~0U;
		*flagsp = flags;
		break;
	case '-':
		*maskp = ~flags;
		*flagsp = 0;
		break;
	}
	if (verbose)
		printk(KERN_INFO "%s: *flagsp=0x%x *maskp=0x%x\n",
			__func__, *flagsp, *maskp);
	return 0;
}

/*
 * File_ops->write method for <debugfs>/dynamic_fault/conrol.  Gathers the
 * command text from userspace, parses and executes it.
 */
static ssize_t dfault_proc_write(struct file *file, const char __user *ubuf,
				  size_t len, loff_t *offp)
{
	unsigned int flags = 0, mask = 0;
	struct dfault_query query;
#define MAXWORDS 9
	int nwords;
	char *words[MAXWORDS];
	char tmpbuf[256];

	if (len == 0)
		return 0;
	/* we don't check *offp -- multiple writes() are allowed */
	if (len > sizeof(tmpbuf)-1)
		return -E2BIG;
	if (copy_from_user(tmpbuf, ubuf, len))
		return -EFAULT;
	tmpbuf[len] = '\0';
	if (verbose)
		printk(KERN_INFO "%s: read %d bytes from userspace\n",
			__func__, (int)len);

	nwords = dfault_tokenize(tmpbuf, words, MAXWORDS);
	if (nwords < 0)
		return -EINVAL;
	if (dfault_parse_query(words, nwords-1, &query))
		return -EINVAL;
	if (dfault_parse_flags(words[nwords-1], &flags, &mask))
		return -EINVAL;

	/* actually go and implement the change */
	dfault_change(&query, flags, mask);

	*offp += len;
	return len;
}

/*
 * Set the iterator to point to the first _dfault object
 * and return a pointer to that first object.  Returns
 * NULL if there are no _dfaults at all.
 */
static struct _dfault *dfault_iter_first(struct dfault_iter *iter)
{
	if (list_empty(&dfault_tables)) {
		iter->table = NULL;
		iter->idx = 0;
		return NULL;
	}
	iter->table = list_entry(dfault_tables.next,
				 struct dfault_table, link);
	iter->idx = 0;
	return &iter->table->dfaults[iter->idx];
}

/*
 * Advance the iterator to point to the next _dfault
 * object from the one the iterator currently points at,
 * and returns a pointer to the new _dfault.  Returns
 * NULL if the iterator has seen all the _dfaults.
 */
static struct _dfault *dfault_iter_next(struct dfault_iter *iter)
{
	if (iter->table == NULL)
		return NULL;
	if (++iter->idx == iter->table->num_dfaults) {
		/* iterate to next table */
		iter->idx = 0;
		if (list_is_last(&iter->table->link, &dfault_tables)) {
			iter->table = NULL;
			return NULL;
		}
		iter->table = list_entry(iter->table->link.next,
					 struct dfault_table, link);
	}
	return &iter->table->dfaults[iter->idx];
}

/*
 * Seq_ops start method.  Called at the start of every
 * read() call from userspace.  Takes the dfault_lock and
 * seeks the seq_file's iterator to the given position.
 */
static void *dfault_proc_start(struct seq_file *m, loff_t *pos)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *dp;
	int n = *pos;

	if (verbose)
		printk(KERN_INFO "%s: called m=%p *pos=%lld\n",
			__func__, m, (unsigned long long)*pos);

	mutex_lock(&dfault_lock);

	if (!n)
		return SEQ_START_TOKEN;
	if (n < 0)
		return NULL;
	dp = dfault_iter_first(iter);
	while (dp != NULL && --n > 0)
		dp = dfault_iter_next(iter);
	return dp;
}

/*
 * Seq_ops next method.  Called several times within a read()
 * call from userspace, with dfault_lock held.  Walks to the
 * next _dfault object with a special case for the header line.
 */
static void *dfault_proc_next(struct seq_file *m, void *p, loff_t *pos)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *dp;

	if (verbose)
		printk(KERN_INFO "%s: called m=%p p=%p *pos=%lld\n",
			__func__, m, p, (unsigned long long)*pos);

	if (p == SEQ_START_TOKEN)
		dp = dfault_iter_first(iter);
	else
		dp = dfault_iter_next(iter);
	++*pos;
	return dp;
}

/*
 * Seq_ops show method.  Called several times within a read()
 * call from userspace, with dfault_lock held.  Formats the
 * current _dfault as a single human-readable line, with a
 * special case for the header line.
 */
static int dfault_proc_show(struct seq_file *m, void *p)
{
	struct dfault_iter *iter = m->private;
	struct _dfault *df = p;
	char flagsbuf[8];

	if (verbose)
		printk(KERN_INFO "%s: called m=%p p=%p\n",
			__func__, m, p);

	if (p == SEQ_START_TOKEN) {
		seq_puts(m,
			"# filename:lineno [module]function flags format\n");
		return 0;
	}

	seq_printf(m, "%s:%u [%s]%s %s \"",
		   df->filename, df->lineno,
		   iter->table->mod_name, df->function,
		   dfault_describe_flags(df, flagsbuf, sizeof(flagsbuf)));
	seq_puts(m, "\"\n");

	return 0;
}

/*
 * Seq_ops stop method.  Called at the end of each read()
 * call from userspace.  Drops dfault_lock.
 */
static void dfault_proc_stop(struct seq_file *m, void *p)
{
	if (verbose)
		printk(KERN_INFO "%s: called m=%p p=%p\n",
			__func__, m, p);
	mutex_unlock(&dfault_lock);
}

static const struct seq_operations dfault_proc_seqops = {
	.start = dfault_proc_start,
	.next = dfault_proc_next,
	.show = dfault_proc_show,
	.stop = dfault_proc_stop
};

/*
 * File_ops->open method for <debugfs>/dynamic_fault/control.  Does the seq_file
 * setup dance, and also creates an iterator to walk the _dfaults.
 * Note that we create a seq_file always, even for O_WRONLY files
 * where it's not needed, as doing so simplifies the ->release method.
 */
static int dfault_proc_open(struct inode *inode, struct file *file)
{
	struct dfault_iter *iter;
	int err;

	if (verbose)
		printk(KERN_INFO "%s: called\n", __func__);

	iter = kzalloc(sizeof(*iter), GFP_KERNEL);
	if (iter == NULL)
		return -ENOMEM;

	err = seq_open(file, &dfault_proc_seqops);
	if (err) {
		kfree(iter);
		return err;
	}
	((struct seq_file *) file->private_data)->private = iter;
	return 0;
}

static const struct file_operations dfault_proc_fops = {
	.owner = THIS_MODULE,
	.open = dfault_proc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = seq_release_private,
	.write = dfault_proc_write
};

/*
 * Allocate a new dfault_table for the given module
 * and add it to the global list.
 */
int dfault_add_module(struct _dfault *tab, unsigned int n,
		      const char *name)
{
	struct dfault_table *dt;
	char *new_name;

	dt = kzalloc(sizeof(*dt), GFP_KERNEL);
	if (dt == NULL)
		return -ENOMEM;
	new_name = kstrdup(name, GFP_KERNEL);
	if (new_name == NULL) {
		kfree(dt);
		return -ENOMEM;
	}
	dt->mod_name = new_name;
	dt->num_dfaults = n;
	dt->num_enabled = 0;
	dt->dfaults = tab;

	mutex_lock(&dfault_lock);
	list_add_tail(&dt->link, &dfault_tables);
	mutex_unlock(&dfault_lock);

	if (verbose)
		printk(KERN_INFO "%u debug prints in module %s\n",
				 n, dt->mod_name);
	return 0;
}
EXPORT_SYMBOL_GPL(dfault_add_module);

static void dfault_table_free(struct dfault_table *dt)
{
	list_del_init(&dt->link);
	kfree(dt->mod_name);
	kfree(dt);
}

/*
 * Called in response to a module being unloaded.  Removes
 * any dfault_table's which point at the module.
 */
int dfault_remove_module(char *mod_name)
{
	struct dfault_table *dt, *nextdt;
	int ret = -ENOENT;

	if (verbose)
		printk(KERN_INFO "%s: removing module \"%s\"\n",
				__func__, mod_name);

	mutex_lock(&dfault_lock);
	list_for_each_entry_safe(dt, nextdt, &dfault_tables, link) {
		if (!strcmp(dt->mod_name, mod_name)) {
			dfault_table_free(dt);
			ret = 0;
		}
	}
	mutex_unlock(&dfault_lock);
	return ret;
}
EXPORT_SYMBOL_GPL(dfault_remove_module);

static void dfault_remove_all_tables(void)
{
	mutex_lock(&dfault_lock);
	while (!list_empty(&dfault_tables)) {
		struct dfault_table *dt = list_entry(dfault_tables.next,
						      struct dfault_table,
						      link);
		dfault_table_free(dt);
	}
	mutex_unlock(&dfault_lock);
}

static int __init dynamic_fault_init(void)
{
	struct dentry *dir, *file;
	struct _dfault *iter, *iter_start;
	const char *modname = NULL;
	int ret = 0;
	int n = 0;

	dir = debugfs_create_dir("dynamic_fault", NULL);
	if (!dir)
		return -ENOMEM;
	file = debugfs_create_file("control", 0644, dir, NULL,
					&dfault_proc_fops);
	if (!file) {
		debugfs_remove(dir);
		return -ENOMEM;
	}
	if (__start___faults != __stop___faults) {
		iter = __start___faults;
		modname = iter->modname;
		iter_start = iter;
		for (; iter < __stop___faults; iter++) {
			if (strcmp(modname, iter->modname)) {
				ret = dfault_add_module(iter_start, n, modname);
				if (ret)
					goto out_free;
				n = 0;
				modname = iter->modname;
				iter_start = iter;
			}
			n++;
		}
		ret = dfault_add_module(iter_start, n, modname);
	}
out_free:
	if (ret) {
		dfault_remove_all_tables();
		debugfs_remove(dir);
		debugfs_remove(file);
	}
	return 0;
}
module_init(dynamic_fault_init);
