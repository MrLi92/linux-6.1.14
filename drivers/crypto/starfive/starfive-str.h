/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STARFIVE_STR_H__
#define __STARFIVE_STR_H__

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>

#include <crypto/engine.h>
#include <crypto/sha2.h>
#include <crypto/sm3.h>

#include "starfive-regs.h"

#define STARFIVE_MSG_BUFFER_SIZE		SZ_16K
#define MAX_KEY_SIZE				SHA512_BLOCK_SIZE

struct starfive_cryp_ctx {
	struct crypto_engine_ctx		enginectx;
	struct starfive_cryp_dev		*cryp;
	struct starfive_cryp_request_ctx	*rctx;
	struct scatterlist			sg[2];

	unsigned int				hash_mode;
	u8					key[MAX_KEY_SIZE];
	int					keylen;
	size_t					hash_len_total;
	u8					*buffer;
	union {
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
	void					*hash_data;

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
		struct ahash_request		*hreq;
	} req;
#define STARFIVE_AHASH_REQ			0
	unsigned int				req_type;

	union {
		union starfive_hash_csr		hash;
	} csr;

	struct scatterlist			*in_sg;

	unsigned long				flags;
	unsigned long				op;

	size_t					bufcnt;
	size_t					buflen;
	size_t					total;
	size_t					offset;
	size_t					data_offset;

	unsigned int				hash_digest_len;
	u8 hash_digest_mid[SHA512_DIGEST_SIZE]__aligned(sizeof(u32));
};

struct starfive_cryp_dev *starfive_cryp_find_dev(struct starfive_cryp_ctx *ctx);

int starfive_hash_register_algs(void);
void starfive_hash_unregister_algs(void);

#endif
