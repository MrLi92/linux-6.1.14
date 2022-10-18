/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STARFIVE_STR_H__
#define __STARFIVE_STR_H__

#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>

#include <crypto/engine.h>

#include "starfive-regs.h"

#define STARFIVE_MSG_BUFFER_SIZE		SZ_16K

struct starfive_cryp_ctx {
	struct crypto_engine_ctx		enginectx;
	struct starfive_cryp_dev		*cryp;

	u8					*buffer;
};

struct starfive_cryp_dev {
	struct list_head			list;
	struct device				*dev;

	struct clk				*hclk;
	struct clk				*ahb;
	struct reset_control			*rst;

	void __iomem				*base;
	phys_addr_t				phys_base;

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

	struct crypto_engine			*engine;

	union starfive_alg_cr			alg_cr;
};

struct starfive_cryp_dev *starfive_cryp_find_dev(struct starfive_cryp_ctx *ctx);

#endif
