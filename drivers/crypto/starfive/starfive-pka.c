// SPDX-License-Identifier: GPL-2.0
/*
 * StarFive Public Key Algo acceleration driver
 *
 * Copyright (c) 2022 StarFive Technology
 */

#include <linux/crypto.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-direct.h>
#include <linux/interrupt.h>
#include <linux/iopoll.h>
#include <linux/io.h>
#include <linux/mod_devicetable.h>

#include <crypto/scatterwalk.h>

#include "starfive-str.h"

#define STARFIVE_RSA_KEYSZ_LEN			(2048 >> 2)
#define STARFIVE_RSA_KEY_SIZE			(STARFIVE_RSA_KEYSZ_LEN * 3)
#define STARFIVE_RSA_MAX_KEYSZ			256

static inline int starfive_pka_wait_done(struct starfive_cryp_ctx *ctx)
{
	struct starfive_cryp_dev *cryp = ctx->cryp;
	u32 status;

	return readl_relaxed_poll_timeout(cryp->base + STARFIVE_PKA_CASR_OFFSET, status,
					  (status & STARFIVE_PKA_DONE_FLAGS), 10, 100000);
}

static void starfive_rsa_free_key(struct starfive_rsa_key *key)
{
	if (key->d)
		kfree_sensitive(key->d);
	if (key->e)
		kfree_sensitive(key->e);
	if (key->n)
		kfree_sensitive(key->n);
	memset(key, 0, sizeof(*key));
}

static unsigned int starfive_rsa_get_nbit(u8 *pa, u32 snum, int key_sz)
{
	u32 i;
	u8 value;

	i = snum >> 3;

	value = pa[key_sz - i - 1];
	value >>= snum & 0x7;
	value &= 0x1;

	return value;
}

static int starfive_rsa_domain_transfer(struct starfive_cryp_ctx *ctx,
					u32 *result, u32 *opa, u8 domain,
					u32 *mod, int bit_len)
{
	struct starfive_cryp_dev *cryp = ctx->cryp;
	struct starfive_cryp_request_ctx *rctx = ctx->rctx;
	unsigned int *info;
	int loop;
	u8 opsize;
	u32 temp;

	opsize = (bit_len - 1) >> 5;
	rctx->csr.pka.v = 0;
	writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

	info = (unsigned int *)mod;
	for (loop = 0; loop <= opsize; loop++)
		writel(info[opsize - loop], cryp->base + STARFIVE_PKA_CANR_OFFSET + loop * 4);

	if (domain != 0) {
		rctx->csr.pka.v = 0;
		rctx->csr.pka.cln_done = 1;
		rctx->csr.pka.opsize = opsize;
		rctx->csr.pka.exposize = opsize;
		rctx->csr.pka.cmd = CRYPTO_CMD_PRE;
		rctx->csr.pka.start = 1;
		rctx->csr.pka.not_r2 = 1;
		writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

		starfive_pka_wait_done(ctx);

		info = (unsigned int *)opa;
		for (loop = 0; loop <= opsize; loop++)
			writel(info[opsize - loop], cryp->base + STARFIVE_PKA_CAAR_OFFSET + loop * 4);

		writel(0x1000000, cryp->base + STARFIVE_PKA_CAER_OFFSET);

		for (loop = 1; loop <= opsize; loop++)
			writel(0, cryp->base + STARFIVE_PKA_CAER_OFFSET + loop * 4);

		rctx->csr.pka.v = 0;
		rctx->csr.pka.cln_done = 1;
		rctx->csr.pka.opsize = opsize;
		rctx->csr.pka.exposize = opsize;
		rctx->csr.pka.cmd = CRYPTO_CMD_AERN;
		rctx->csr.pka.start = 1;
		writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

		starfive_pka_wait_done(ctx);
	} else {
		rctx->csr.pka.v = 0;
		rctx->csr.pka.cln_done = 1;
		rctx->csr.pka.opsize = opsize;
		rctx->csr.pka.exposize = opsize;
		rctx->csr.pka.cmd = CRYPTO_CMD_PRE;
		rctx->csr.pka.start = 1;
		rctx->csr.pka.pre_expf = 1;
		writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

		starfive_pka_wait_done(ctx);

		info = (unsigned int *)opa;
		for (loop = 0; loop <= opsize; loop++)
			writel(info[opsize - loop], cryp->base + STARFIVE_PKA_CAER_OFFSET + loop * 4);

		rctx->csr.pka.v = 0;
		rctx->csr.pka.cln_done = 1;
		rctx->csr.pka.opsize = opsize;
		rctx->csr.pka.exposize = opsize;
		rctx->csr.pka.cmd = CRYPTO_CMD_ARN;
		rctx->csr.pka.start = 1;
		writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

		starfive_pka_wait_done(ctx);
	}

	for (loop = 0; loop <= opsize; loop++) {
		temp = readl(cryp->base + STARFIVE_PKA_CAAR_OFFSET + 0x4 * loop);
		result[opsize - loop] = temp;
	}

	return 0;
}

static int starfive_rsa_cpu_powm(struct starfive_cryp_ctx *ctx, u32 *result,
				 u8 *de, u32 *n, int key_sz)
{
	struct starfive_cryp_dev *cryp = ctx->cryp;
	struct starfive_cryp_request_ctx *rctx = ctx->rctx;
	struct starfive_rsa_key *key = &ctx->rsa_key;
	u32 initial;
	int opsize, mlen, bs, loop;
	unsigned int *mta;

	opsize = (key_sz - 1) >> 2;
	initial = 1;

	mta = kmalloc(key_sz, GFP_KERNEL);
	if (!mta)
		return -ENOMEM;

	starfive_rsa_domain_transfer(ctx, mta, cryp->pka_data, 0, n, key_sz << 3);

	for (loop = 0; loop <= opsize; loop++)
		writel(n[opsize - loop], cryp->base + STARFIVE_PKA_CANR_OFFSET + loop * 4);

	rctx->csr.pka.v = 0;
	rctx->csr.pka.cln_done = 1;
	rctx->csr.pka.opsize = opsize;
	rctx->csr.pka.exposize = opsize;
	rctx->csr.pka.cmd = CRYPTO_CMD_PRE;
	rctx->csr.pka.not_r2 = 1;
	rctx->csr.pka.start = 1;

	writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

	starfive_pka_wait_done(ctx);

	for (loop = 0; loop <= opsize; loop++)
		writel(mta[opsize - loop], cryp->base + STARFIVE_PKA_CAER_OFFSET + loop * 4);

	for (loop = key->bitlen; loop > 0; loop--) {
		if (initial) {
			for (bs = 0; bs <= opsize; bs++)
				result[bs] = mta[bs];

			initial = 0;
		} else {
			mlen = starfive_rsa_get_nbit(de, loop - 1, key_sz);

			rctx->csr.pka.v = 0;
			rctx->csr.pka.cln_done = 1;
			rctx->csr.pka.opsize = opsize;
			rctx->csr.pka.exposize = opsize;
			rctx->csr.pka.cmd = CRYPTO_CMD_AARN;
			rctx->csr.pka.start = 1;

			writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);
			starfive_pka_wait_done(ctx);

			if (mlen) {
				rctx->csr.pka.v = 0;
				rctx->csr.pka.cln_done = 1;
				rctx->csr.pka.opsize = opsize;
				rctx->csr.pka.exposize = opsize;
				rctx->csr.pka.cmd = CRYPTO_CMD_AERN;
				rctx->csr.pka.start = 1;

				writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);
				starfive_pka_wait_done(ctx);
			}
		}
	}

	for (loop = 0; loop <= opsize; loop++) {
		unsigned int temp;

		temp = readl(cryp->base + STARFIVE_PKA_CAAR_OFFSET + 0x4 * loop);
		result[opsize - loop] = temp;
	}

	kfree(mta);

	return starfive_rsa_domain_transfer(ctx, result, result, 1, n, key_sz << 3);
}

static int starfive_rsa_powm(struct starfive_cryp_ctx *ctx, u8 *result,
			     u8 *de, u8 *n, int key_sz)
{
	return starfive_rsa_cpu_powm(ctx, (u32 *)result, de, (u32 *)n, key_sz);
}

static int starfive_rsa_get_from_sg(struct starfive_cryp_request_ctx *rctx,
				    size_t offset, size_t count, size_t data_offset)
{
	size_t of, ct, index;
	struct scatterlist	*sg = rctx->in_sg;

	of = offset;
	ct = count;

	while (sg->length <= of) {
		of -= sg->length;

		if (!sg_is_last(sg)) {
			sg = sg_next(sg);
			continue;
		} else {
			return -EBADE;
		}
	}

	index = data_offset;
	while (ct > 0) {
		if (sg->length - of >= ct) {
			scatterwalk_map_and_copy(rctx->cryp->pka_data + index, sg,
						 of, ct, 0);
			index = index + ct;
			return index - data_offset;
		}

		scatterwalk_map_and_copy(rctx->cryp->pka_data + index,
					 sg, of, sg->length - of, 0);
		index += sg->length - of;
		ct = ct - (sg->length - of);

		of = 0;

		if (!sg_is_last(sg))
			sg = sg_next(sg);
		else
			return -EBADE;
	}

	return index - data_offset;
}

static int starfive_rsa_enc_core(struct starfive_cryp_ctx *ctx, int enc)
{
	struct starfive_cryp_dev *cryp = ctx->cryp;
	struct starfive_cryp_request_ctx *rctx = ctx->rctx;
	struct starfive_rsa_key *key = &ctx->rsa_key;
	size_t data_len, total, count, data_offset;
	int ret = 0;
	unsigned int *info;
	int loop;

	rctx->csr.pka.v = 0;
	rctx->csr.pka.reset = 1;
	writel(rctx->csr.pka.v, cryp->base + STARFIVE_PKA_CACR_OFFSET);

	if (starfive_pka_wait_done(ctx))
		dev_dbg(cryp->dev, "this is debug for lophyel pka_casr = %x %s %s %d\n",
			readl(cryp->base + STARFIVE_PKA_CASR_OFFSET),
			__FILE__, __func__, __LINE__);

	rctx->offset = 0;
	total = 0;

	while (total < rctx->total_in) {
		count = min(cryp->data_buf_len, rctx->total_in);
		count = min(count, key->key_sz);
		memset(cryp->pka_data, 0, key->key_sz);
		data_offset = key->key_sz - count;

		data_len = starfive_rsa_get_from_sg(rctx, rctx->offset, count, data_offset);
		if (data_len < 0)
			return data_len;
		if (data_len != count)
			return -EINVAL;

		if (enc) {
			key->bitlen = key->e_bitlen;
			ret = starfive_rsa_powm(ctx, cryp->pka_data + STARFIVE_RSA_KEYSZ_LEN,
						key->e, key->n, key->key_sz);
		} else {
			key->bitlen = key->d_bitlen;
			ret = starfive_rsa_powm(ctx, cryp->pka_data + STARFIVE_RSA_KEYSZ_LEN,
						key->d, key->n, key->key_sz);
		}

		if (ret)
			return ret;

		info = (unsigned int *)(cryp->pka_data + STARFIVE_RSA_KEYSZ_LEN);
		for (loop = 0; loop < key->key_sz >> 2; loop++)
			dev_dbg(cryp->dev, "result[%d] = %x\n", loop, info[loop]);

		sg_copy_buffer(rctx->out_sg, sg_nents(rctx->out_sg),
			       cryp->pka_data + STARFIVE_RSA_KEYSZ_LEN,
			       key->key_sz, rctx->offset, 0);

		rctx->offset += data_len;
		total += data_len;
	}

	return ret;
}

static int starfive_rsa_enc(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct starfive_rsa_key *key = &ctx->rsa_key;
	struct starfive_cryp_request_ctx *rctx = akcipher_request_ctx(req);
	int ret = 0;

	if (key->key_sz > STARFIVE_RSA_MAX_KEYSZ) {
		akcipher_request_set_tfm(req, ctx->fallback.akcipher);
		ret = crypto_akcipher_encrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}

	if (unlikely(!key->n || !key->e))
		return -EINVAL;

	if (req->dst_len < key->key_sz) {
		req->dst_len = key->key_sz;
		dev_err(ctx->cryp->dev, "Output buffer length less than parameter n\n");
		return -EOVERFLOW;
	}

	mutex_lock(&ctx->cryp->lock);

	rctx->in_sg = req->src;
	rctx->out_sg = req->dst;
	rctx->cryp = ctx->cryp;
	ctx->rctx = rctx;
	rctx->total_in = req->src_len;
	rctx->total_out = req->dst_len;

	ret = starfive_rsa_enc_core(ctx, 1);

	mutex_unlock(&ctx->cryp->lock);

	return ret;
}

static int starfive_rsa_dec(struct akcipher_request *req)
{
	struct crypto_akcipher *tfm = crypto_akcipher_reqtfm(req);
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct starfive_rsa_key *key = &ctx->rsa_key;
	struct starfive_cryp_request_ctx *rctx = akcipher_request_ctx(req);
	int ret = 0;

	if (key->key_sz > STARFIVE_RSA_MAX_KEYSZ) {
		akcipher_request_set_tfm(req, ctx->fallback.akcipher);
		ret = crypto_akcipher_decrypt(req);
		akcipher_request_set_tfm(req, tfm);
		return ret;
	}

	if (unlikely(!key->n || !key->d))
		return -EINVAL;

	if (req->dst_len < key->key_sz) {
		req->dst_len = key->key_sz;
		dev_err(ctx->cryp->dev, "Output buffer length less than parameter n\n");
		return -EOVERFLOW;
	}

	mutex_lock(&ctx->cryp->lock);

	rctx->in_sg = req->src;
	rctx->out_sg = req->dst;
	rctx->cryp = ctx->cryp;
	ctx->rctx = rctx;
	rctx->total_in = req->src_len;
	rctx->total_out = req->dst_len;

	ret = starfive_rsa_enc_core(ctx, 0);

	mutex_unlock(&ctx->cryp->lock);

	return ret;
}

static unsigned long starfive_rsa_check_keysz(unsigned int len)
{
	unsigned int bitslen = len << 3;

	if (bitslen & 0x1f)
		return -EINVAL;

	return 0;
}

static int starfive_rsa_set_n(struct starfive_rsa_key *rsa_key,
			      const char *value, size_t vlen)
{
	const char *ptr = value;
	int ret;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	rsa_key->key_sz = vlen;

	/* invalid key size provided */
	ret = starfive_rsa_check_keysz(rsa_key->key_sz);
	if (ret)
		return ret;

	ret = -ENOMEM;
	rsa_key->n = kmemdup(ptr, rsa_key->key_sz, GFP_KERNEL);
	if (!rsa_key->n)
		goto err;

	return 0;
 err:
	rsa_key->key_sz = 0;
	rsa_key->n = NULL;
	starfive_rsa_free_key(rsa_key);
	return ret;
}

static int starfive_rsa_set_e(struct starfive_rsa_key *rsa_key,
			      const char *value, size_t vlen)
{
	const char *ptr = value;
	unsigned char pt;
	int loop;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	pt = *ptr;

	if (!rsa_key->key_sz || !vlen || vlen > rsa_key->key_sz) {
		rsa_key->e = NULL;
		return -EINVAL;
	}

	rsa_key->e = kzalloc(rsa_key->key_sz, GFP_KERNEL);
	if (!rsa_key->e)
		return -ENOMEM;

	for (loop = 8; loop > 0; loop--) {
		if (pt >> (loop - 1))
			break;
	}

	rsa_key->e_bitlen = (vlen - 1) * 8 + loop;

	memcpy(rsa_key->e + (rsa_key->key_sz - vlen), ptr, vlen);

	return 0;
}

static int starfive_rsa_set_d(struct starfive_rsa_key *rsa_key,
			      const char *value, size_t vlen)
{
	const char *ptr = value;
	unsigned char pt;
	int loop;
	int ret;

	while (!*ptr && vlen) {
		ptr++;
		vlen--;
	}
	pt = *ptr;

	ret = -EINVAL;
	if (!rsa_key->key_sz || !vlen || vlen > rsa_key->key_sz)
		goto err;

	ret = -ENOMEM;
	rsa_key->d = kzalloc(rsa_key->key_sz, GFP_KERNEL);
	if (!rsa_key->d)
		goto err;

	for (loop = 8; loop > 0; loop--) {
		pr_debug("this is debug for lophyel loop = %d pt >> (loop - 1) = %x value[%d] = %x %s %s %d\n",
			 loop, pt >> (loop - 1), loop, value[loop], __FILE__, __func__, __LINE__);
		if (pt >> (loop - 1))
			break;
	}

	rsa_key->d_bitlen = (vlen - 1) * 8 + loop;

	memcpy(rsa_key->d + (rsa_key->key_sz - vlen), ptr, vlen);

	return 0;
 err:
	rsa_key->d = NULL;
	return ret;
}

static int starfive_rsa_setkey(struct crypto_akcipher *tfm, const void *key,
			       unsigned int keylen, bool private)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct rsa_key raw_key = {NULL};
	struct starfive_rsa_key *rsa_key = &ctx->rsa_key;
	int ret;

	starfive_rsa_free_key(rsa_key);

	if (private)
		ret = rsa_parse_priv_key(&raw_key, key, keylen);
	else
		ret = rsa_parse_pub_key(&raw_key, key, keylen);
	if (ret < 0)
		goto err;

	ret = starfive_rsa_set_n(rsa_key, raw_key.n, raw_key.n_sz);
	if (ret < 0)
		return ret;

	ret = starfive_rsa_set_e(rsa_key, raw_key.e, raw_key.e_sz);
	if (ret < 0)
		goto err;

	if (private) {
		ret = starfive_rsa_set_d(rsa_key, raw_key.d, raw_key.d_sz);
		if (ret < 0)
			goto err;
	}

	if (!rsa_key->n || !rsa_key->e) {
		/* invalid key provided */
		ret = -EINVAL;
		goto err;
	}
	if (private && !rsa_key->d) {
		/* invalid private key provided */
		ret = -EINVAL;
		goto err;
	}

	return 0;
 err:
	starfive_rsa_free_key(rsa_key);
	return ret;
}

static int starfive_rsa_set_pub_key(struct crypto_akcipher *tfm, const void *key,
				    unsigned int keylen)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ret = crypto_akcipher_set_pub_key(ctx->fallback.akcipher, key, keylen);
	if (ret)
		return ret;

	return starfive_rsa_setkey(tfm, key, keylen, false);
}

static int starfive_rsa_set_priv_key(struct crypto_akcipher *tfm, const void *key,
				     unsigned int keylen)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	int ret;

	ret = crypto_akcipher_set_priv_key(ctx->fallback.akcipher, key, keylen);
	if (ret)
		return ret;

	return starfive_rsa_setkey(tfm, key, keylen, true);
}

static unsigned int starfive_rsa_max_size(struct crypto_akcipher *tfm)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);

	/* For key sizes > 2Kb, use software tfm */
	if (ctx->rsa_key.key_sz > STARFIVE_RSA_MAX_KEYSZ)
		return crypto_akcipher_maxsize(ctx->fallback.akcipher);

	return ctx->rsa_key.key_sz;
}

/* Per session pkc's driver context creation function */
static int starfive_rsa_init_tfm(struct crypto_akcipher *tfm)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);

	ctx->fallback.akcipher = crypto_alloc_akcipher("rsa-generic", 0, 0);
	if (IS_ERR(ctx->fallback.akcipher))
		return PTR_ERR(ctx->fallback.akcipher);

	ctx->cryp = starfive_cryp_find_dev(ctx);
	if (!ctx->cryp) {
		crypto_free_akcipher(ctx->fallback.akcipher);
		return -ENODEV;
	}

	akcipher_set_reqsize(tfm, sizeof(struct starfive_cryp_request_ctx));

	return 0;
}

/* Per session pkc's driver context cleanup function */
static void starfive_rsa_exit_tfm(struct crypto_akcipher *tfm)
{
	struct starfive_cryp_ctx *ctx = akcipher_tfm_ctx(tfm);
	struct starfive_rsa_key *key = (struct starfive_rsa_key *)&ctx->rsa_key;

	crypto_free_akcipher(ctx->fallback.akcipher);
	starfive_rsa_free_key(key);
}

static struct akcipher_alg starfive_rsa = {
	.encrypt = starfive_rsa_enc,
	.decrypt = starfive_rsa_dec,
	.sign = starfive_rsa_dec,
	.verify = starfive_rsa_enc,
	.set_pub_key = starfive_rsa_set_pub_key,
	.set_priv_key = starfive_rsa_set_priv_key,
	.max_size = starfive_rsa_max_size,
	.init = starfive_rsa_init_tfm,
	.exit = starfive_rsa_exit_tfm,
	.reqsize = sizeof(struct starfive_cryp_request_ctx),
	.base = {
		.cra_name = "rsa",
		.cra_driver_name = "starfive-rsa",
		.cra_flags = CRYPTO_ALG_TYPE_AKCIPHER |
			     CRYPTO_ALG_ASYNC |
			     CRYPTO_ALG_NEED_FALLBACK,
		.cra_priority = 3000,
		.cra_module = THIS_MODULE,
		.cra_ctxsize = sizeof(struct starfive_cryp_ctx),
	},
};

int starfive_pka_register_algs(void)
{
	return crypto_register_akcipher(&starfive_rsa);
}

void starfive_pka_unregister_algs(void)
{
	crypto_unregister_akcipher(&starfive_rsa);
}
