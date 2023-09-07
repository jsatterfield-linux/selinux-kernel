// SPDX-License-Identifier: GPL-2.0
/*
 * Implementation of the hash table type.
 *
 * Author : Stephen Smalley, <stephen.smalley.work@gmail.com>
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include "hashtab.h"
#include "security.h"

/*
 * Here we simply round the number of elements up to the nearest power of two.
 * I tried also other options like rounding down or rounding to the closest
 * power of two (up or down based on which is closer), but I was unable to
 * find any significant difference in lookup/insert performance that would
 * justify switching to a different (less intuitive) formula. It could be that
 * a different formula is actually more optimal, but any future changes here
 * should be supported with performance/memory usage data.
 *
 * The total memory used by the htable arrays (only) with Fedora policy loaded
 * is approximately 163 KB at the time of writing.
 */
static u32 hashtab_compute_size(u32 nel)
{
	return nel == 0 ? 0 : roundup_pow_of_two(nel);
}

int hashtab_init(struct hashtab *h, u32 nel_hint)
{
	u32 size = hashtab_compute_size(nel_hint);

	/* should already be zeroed, but better be safe */
	h->nel = 0;
	h->size = 0;
	h->htable = NULL;

	if (size) {
		h->htable = kcalloc(size, sizeof(*h->htable), GFP_KERNEL);
		if (!h->htable)
			goto err;
		h->nodes = kcalloc(nel_hint, sizeof(*h->nodes), GFP_KERNEL);
		if (!h->nodes)
			goto htable;
		h->size = size;
		h->nnodes = nel_hint;
	}
	return 0;
htable:
	kfree(h->htable);
	h->htable = NULL;
err:
	return -ENOMEM;
}

int __hashtab_insert(struct hashtab *h, u32 *dst, void *key, void *datum)
{
	u32 newnodei;
	struct hashtab_node *newnode;

	newnodei = ++h->nel;
	newnode = hashtab_get_node(h, newnodei);

	newnode->key = key;
	newnode->datum = datum;
	newnode->next = *dst;
	*dst = newnodei;

	return 0;
}

void hashtab_destroy(struct hashtab *h)
{
	kfree(h->nodes);
	kfree(h->htable);
	memset(h, 0, sizeof(*h));
}

int hashtab_map(struct hashtab *h, int (*apply)(void *k, void *d, void *args),
		void *args)
{
	u32 i;
	int ret;
	struct hashtab_node *cur;

	for (i = 0; i < h->size; i++) {
		cur = hashtab_get_chain(h, i);
		while (cur) {
			ret = apply(cur->key, cur->datum, args);
			if (ret)
				return ret;
			cur = hashtab_get_node(h, cur->next);
		}
	}
	return 0;
}

#ifdef CONFIG_SECURITY_SELINUX_DEBUG
void hashtab_stat(struct hashtab *h, struct hashtab_info *info)
{
	u32 i, chain_len, slots_used, max_chain_len;
	u64 chain2_len_sum;
	struct hashtab_node *cur;

	slots_used = 0;
	max_chain_len = 0;
	chain2_len_sum = 0;
	for (i = 0; i < h->size; i++) {
		cur = hashtab_get_chain(h, i);
		if (cur) {
			slots_used++;
			chain_len = 0;
			while (cur) {
				chain_len++;
				cur = hashtab_get_node(h, cur->next);
			}

			if (chain_len > max_chain_len)
				max_chain_len = chain_len;

			chain2_len_sum += (u64)chain_len * chain_len;
		}
	}

	info->slots_used = slots_used;
	info->max_chain_len = max_chain_len;
	info->chain2_len_sum = chain2_len_sum;
}
#endif /* CONFIG_SECURITY_SELINUX_DEBUG */

int hashtab_duplicate(struct hashtab *new, const struct hashtab *orig,
		      int (*copy)(struct hashtab_node *new,
				  const struct hashtab_node *orig, void *args),
		      int (*destroy)(void *k, void *d, void *args), void *args)
{
	struct hashtab_node *cur;
	u32 i;
	int rc;

	memset(new, 0, sizeof(*new));

	new->htable = kcalloc(orig->size, sizeof(*new->htable), GFP_KERNEL);
	if (!new->htable)
		return -ENOMEM;
	new->nodes = kcalloc(orig->nnodes, sizeof(*new->nodes), GFP_KERNEL);
	if (!new->nodes)
		goto htable;

	new->size = orig->size;
	new->nnodes = orig->nnodes;

	memcpy(new->htable, orig->htable, sizeof(*new->htable) * orig->size);
	memcpy(new->nodes, orig->nodes, sizeof(*new->nodes) * orig->nnodes);
	for (i = 0; i < orig->nel; i++) {
		rc = copy(&new->nodes[i], &orig->nodes[i], args);
		if (rc)
			goto nodes;
		new->nel++;
	}

	return 0;

nodes:
	for (i = 0; i < new->nel; i++) {
		cur = hashtab_get_node(new, i);
		destroy(cur->key, cur->datum, args);
	}
	kfree(new->nodes);
htable:
	kfree(new->htable);
	memset(new, 0, sizeof(*new));
	return -ENOMEM;
}
