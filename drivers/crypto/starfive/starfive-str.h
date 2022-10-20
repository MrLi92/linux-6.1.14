/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STARFIVE_STR_H__
#define __STARFIVE_STR_H__

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>

#include <crypto/aes.h>
#include <crypto/engine.h>
#include <crypto/sha2.h>
#include <crypto/sm3.h>
#include <crypto/internal/akcipher.h>
#include <crypto/internal/rsa.h>

#include "starfive-regs.h"

#define STARFIVE_MSG_BUFFER_SIZE		SZ_16K
#define MAX_KEY_SIZE				SHA512_BLOCK_SIZE
#define STARFIVE_AES_IV_LEN			AES_BLOCK_SIZE
#define STARFIVE_AES_CTR_LEN			AES_BLOCK_SIZE

struct starfive_rsa_key {
	u8					*n;
	u8					*e;
	u8					*d;
	u8					*p;
	u8					*q;
	u8					*dp;
	u8					*dq;
	u8					*qinv;
	u8					*rinv;
	u8					*rinv_p;
	u8					*rinv_q;
	u8					*mp;
	u8					*rsqr;
	u8					*rsqr_p;
	u8					*rsqr_q;
	u8					*pmp;
	u8					*qmp;
	int					e_bitlen;
	int					d_bitlen;
	int					bitlen;
	size_t					key_sz;
	bool					crt_mode;
};

struct starfive_cryp_ctx {
	struct crypto_engine_ctx		enginectx;
	struct starfive_cryp_dev		*cryp;
	struct starfive_cryp_request_ctx	*rctx;
	struct scatterlist			sg[2];

	unsigned int				hash_mode;
	u8					key[MAX_KEY_SIZE];
	int					keylen;
	size_t					hash_len_total;
	size_t					rsa_key_sz;
	struct starfive_rsa_key			rsa_key;
	u8					*buffer;
	union {
		struct crypto_akcipher		*akcipher;
		struct crypto_aead		*aead;
		struct crypto_shash		*shash;
	} fallback;
	bool                                    fallback_available;
};

struct starfive_cryp_dev {
	struct list_head			list;
	struct device				*dev;
	struct clk				*hclk;
	struct clk				*ahb;
	struct reset_control			*rst;
	void __iomem				*base;
	phys_addr_t				phys_base;
	void					*aes_data;
	void					*hash_data;
	void					*pka_data;
	size_t					data_buf_len;
	int					pages_count;
	u32					dma_maxburst;
	bool					side_chan;
	struct dma_chan				*tx;
	struct dma_chan				*rx;
	struct dma_slave_config			cfg_in;
	struct dma_slave_config			cfg_out;
	struct completion			tx_comp;
	struct completion			rx_comp;
	/* To synchronize concurrent request from different
	 * crypto module accessing the hardware engine.
	 */
	struct mutex				lock;
	struct crypto_engine			*engine;
	union starfive_alg_cr			alg_cr;
};

struct starfive_cryp_request_ctx {
	struct starfive_cryp_ctx		*ctx;
	struct starfive_cryp_dev		*cryp;
	union {
		struct aead_request		*areq;
		struct ahash_request		*hreq;
		struct skcipher_request		*sreq;
	} req;
#define STARFIVE_AHASH_REQ			0
#define STARFIVE_ABLK_REQ			1
#define STARFIVE_AEAD_REQ			2
	unsigned int				req_type;
	union {
		union starfive_aes_csr		aes;
		union starfive_hash_csr		hash;
		union starfive_pka_cacr		pka;
	} csr;
	struct scatterlist			*in_sg;
	struct scatterlist			*out_sg;
	struct scatterlist			*out_sg_save;
	struct scatterlist			in_sgl;
	struct scatterlist			out_sgl;
	bool					sgs_copied;
	unsigned long				sg_len;
	unsigned long				in_sg_len;
	unsigned long				out_sg_len;
	unsigned long				flags;
	unsigned long				op;
	unsigned long				stmode;
	size_t					bufcnt;
	size_t					buflen;
	size_t					total;
	size_t					offset;
	size_t					data_offset;
	size_t					authsize;
	size_t					hw_blocksize;
	size_t					total_in;
	size_t					total_in_save;
	size_t					total_out;
	size_t					total_out_save;
	size_t					assoclen;
	size_t					ctr_over_count;
	u32					ctr[4];
	u32					aes_iv[4];
	u32					tag_out[4];
	u32					tag_in[4];
	unsigned int				hash_digest_len;
	u8 hash_digest_mid[SHA512_DIGEST_SIZE]__aligned(sizeof(u32));
};

struct starfive_cryp_dev *starfive_cryp_find_dev(struct starfive_cryp_ctx *ctx);

int starfive_hash_register_algs(void);
void starfive_hash_unregister_algs(void);

int starfive_aes_register_algs(void);
void starfive_aes_unregister_algs(void);

int starfive_pka_register_algs(void);
void starfive_pka_unregister_algs(void);

#endif
