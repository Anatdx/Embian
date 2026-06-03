/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Embian - bmax-style arm64 kernel table patch helper.
 *
 * Derived from the KernelSU/Kasumi arm64 patch_memory helper.
 */

#define pr_fmt(fmt) "embian: patch: " fmt

#ifdef __aarch64__

#include <linux/atomic.h>
#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/mm.h>
#include <linux/printk.h>
#include <linux/stop_machine.h>
#include <linux/string.h>
#include <asm/cacheflush.h>
#include <asm/fixmap.h>

#include "embian.h"

typedef void (*embian_set_fixmap_fn)(enum fixed_addresses idx,
				     phys_addr_t phys, pgprot_t prot);
typedef void (*embian_cache_range_fn)(unsigned long start,
				      unsigned long end);
typedef void (*embian_cache_area_fn)(void *addr, size_t size);

static struct mm_struct *embian_init_mm;
static embian_set_fixmap_fn embian_set_fixmap;
static embian_cache_range_fn embian_dcache_clean_inval_poc;
static embian_cache_range_fn embian_caches_clean_inval_pou;
static embian_cache_area_fn embian_flush_dcache_area;

struct embian_patch_info {
	void *dst;
	const void *src;
	size_t len;
	atomic_t cpu_count;
};

static int embian_patch_resolve_symbols(void)
{
	if (!embian_init_mm)
		embian_init_mm = (void *)embian_lookup_name("init_mm");
	if (!embian_set_fixmap)
		embian_set_fixmap = (void *)embian_lookup_name("__set_fixmap");
	if (!embian_dcache_clean_inval_poc)
		embian_dcache_clean_inval_poc =
			(void *)embian_lookup_name_quiet("dcache_clean_inval_poc");
	if (!embian_flush_dcache_area)
		embian_flush_dcache_area =
			(void *)embian_lookup_name_quiet("__flush_dcache_area");
	if (!embian_caches_clean_inval_pou)
		embian_caches_clean_inval_pou =
			(void *)embian_lookup_name_quiet("caches_clean_inval_pou");

	if (!embian_init_mm || !embian_set_fixmap) {
		pr_warn("missing patch symbols init_mm=%px __set_fixmap=%px\n",
			embian_init_mm, embian_set_fixmap);
		return -ENOENT;
	}

	return 0;
}

static EMBIAN_NOCFI void embian_patch_flush_dcache(unsigned long start,
						  size_t size)
{
	if (embian_dcache_clean_inval_poc) {
		embian_dcache_clean_inval_poc(start, start + size);
		return;
	}

	if (embian_flush_dcache_area) {
		embian_flush_dcache_area((void *)start, size);
		return;
	}

	if (embian_caches_clean_inval_pou)
		embian_caches_clean_inval_pou(start, start + size);
}

static unsigned long embian_patch_phys_from_virt(unsigned long addr, int *err)
{
	struct mm_struct *mm = embian_init_mm;
	pgd_t *pgd;
	p4d_t *p4d;
	pud_t *pud;
	pmd_t *pmd;
	pte_t *pte;

	*err = 0;
	if (!mm)
		goto fail;

	pgd = pgd_offset(mm, addr);
	if (pgd_none(*pgd) || pgd_bad(*pgd))
		goto fail;

	p4d = p4d_offset(pgd, addr);
	if (p4d_none(*p4d) || p4d_bad(*p4d))
		goto fail;
#if defined(p4d_leaf)
	if (p4d_leaf(*p4d))
		return __p4d_to_phys(*p4d) + (addr & ~P4D_MASK);
#endif

	pud = pud_offset(p4d, addr);
	if (pud_none(*pud) || pud_bad(*pud))
		goto fail;
#if defined(pud_leaf)
	if (pud_leaf(*pud))
		return __pud_to_phys(*pud) + (addr & ~PUD_MASK);
#endif

	pmd = pmd_offset(pud, addr);
#if defined(pmd_leaf)
	if (pmd_leaf(*pmd))
		return __pmd_to_phys(*pmd) + (addr & ~PMD_MASK);
#endif
	if (pmd_none(*pmd) || pmd_bad(*pmd))
		goto fail;

	pte = pte_offset_kernel(pmd, addr);
	if (!pte || !pte_present(*pte))
		goto fail;

	return __pte_to_phys(*pte) + (addr & ~PAGE_MASK);

fail:
	*err = -ENOENT;
	return 0;
}

static EMBIAN_NOCFI int embian_patch_text_nosync(void *dst, const void *src,
						 size_t len)
{
	unsigned long target = (unsigned long)dst;
	unsigned long phys;
	void *map;
	int err;

	phys = embian_patch_phys_from_virt(target, &err);
	if (err)
		return err;

	embian_set_fixmap(FIX_TEXT_POKE0, phys, FIXMAP_PAGE_NORMAL);
	map = (void *)(fix_to_virt(FIX_TEXT_POKE0) + (phys & ~PAGE_MASK));
	memcpy(map, src, len);
	embian_set_fixmap(FIX_TEXT_POKE0, 0, FIXMAP_PAGE_CLEAR);
	embian_patch_flush_dcache(target, len);
	return 0;
}

static int embian_patch_text_cb(void *arg)
{
	struct embian_patch_info *info = arg;
	int ret = 0;

	if (atomic_inc_return(&info->cpu_count) == num_online_cpus()) {
		ret = embian_patch_text_nosync(info->dst, info->src,
					       info->len);
		atomic_inc(&info->cpu_count);
	} else {
		while (atomic_read(&info->cpu_count) <= num_online_cpus())
			cpu_relax();
		isb();
	}

	return ret;
}

int embian_patch_text(void *dst, const void *src, size_t len)
{
	struct embian_patch_info info = {
		.dst = dst,
		.src = src,
		.len = len,
		.cpu_count = ATOMIC_INIT(0),
	};
	int ret;

	ret = embian_patch_resolve_symbols();
	if (ret)
		return ret;

	return stop_machine(embian_patch_text_cb, &info, cpu_online_mask);
}

#else

#include <linux/errno.h>

#include "embian.h"

int embian_patch_text(void *dst, const void *src, size_t len)
{
	return -EOPNOTSUPP;
}

#endif /* __aarch64__ */
