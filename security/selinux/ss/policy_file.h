/* SPDX-License-Identifier: GPL-2.0-only */
/*
 * Types for the policy database struct defined in policydb.h
 * cannot be defined due to circular header references.
 *
 * Author : Jacob Satterfield, <jsatterfield.linux@gmail.com>
 */
#ifndef _SS_POLICY_FILE_H_
#define _SS_POLICY_FILE_H_

#include <linux/errno.h>
#include <linux/types.h>

struct policy_file {
	char *data;
	size_t len;
};

static inline int next_entry(void *buf, struct policy_file *fp, size_t bytes)
{
	if (bytes > fp->len)
		return -EINVAL;

	memcpy(buf, fp->data, bytes);
	fp->data += bytes;
	fp->len -= bytes;
	return 0;
}

static inline int __next_u32_entries(struct policy_file *fp, u32 *out[], size_t len)
{
	int rc;
	__le32 tmp[len];

	rc = next_entry(tmp, fp, sizeof(tmp));
	if (rc < 0)
		return rc;
	for (int i = 0; i < len; i++)
		*out[i] = le32_to_cpu(tmp[i]);
	return 0;
}

#define _next_u32_entries(fp, arr) __next_u32_entries(fp, arr, ARRAY_SIZE(arr))
#define next_u32_entries(fp, ...) _next_u32_entries(fp, ((u32 *[]) {__VA_ARGS__}))

#endif	/* _SS_POLICY_FILE_H_ */
