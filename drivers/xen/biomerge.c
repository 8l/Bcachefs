#include <linux/bio.h>
#include <linux/io.h>
#include <linux/export.h>
#include <xen/page.h>

bool xen_page_phys_mergeable(const struct page *p1, const struct page *p2)
{
	unsigned long mfn1 = pfn_to_mfn(page_to_pfn(p1));
	unsigned long mfn2 = pfn_to_mfn(page_to_pfn(p2));

	return mfn1 + 1 == mfn2;
}
