/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STARFIVE_REGS_H__
#define __STARFIVE_REGS_H__

#define STARFIVE_ALG_CR_OFFSET			0x0
#define STARFIVE_ALG_FIFO_OFFSET		0x4
#define STARFIVE_IE_MASK_OFFSET			0x8
#define STARFIVE_IE_FLAG_OFFSET			0xc
#define STARFIVE_DMA_IN_LEN_OFFSET		0x10
#define STARFIVE_DMA_OUT_LEN_OFFSET		0x14

#define STARFIVE_HASH_REGS_OFFSET		0x300

union starfive_alg_cr {
	u32 v;
	struct {
		u32 start			:1;
		u32 aes_dma_en			:1;
		u32 rsvd_0			:1;
		u32 hash_dma_en			:1;
		u32 alg_done			:1;
		u32 rsvd_1			:3;
		u32 clear			:1;
		u32 rsvd_2			:23;
	};
};

#define STARFIVE_HASH_SHACSR			(STARFIVE_HASH_REGS_OFFSET + 0x0)
#define STARFIVE_HASH_SHAWDR			(STARFIVE_HASH_REGS_OFFSET + 0x4)
#define STARFIVE_HASH_SHARDR			(STARFIVE_HASH_REGS_OFFSET + 0x8)
#define STARFIVE_HASH_SHAWSR			(STARFIVE_HASH_REGS_OFFSET + 0xC)
#define STARFIVE_HASH_SHAWLEN3			(STARFIVE_HASH_REGS_OFFSET + 0x10)
#define STARFIVE_HASH_SHAWLEN2			(STARFIVE_HASH_REGS_OFFSET + 0x14)
#define STARFIVE_HASH_SHAWLEN1			(STARFIVE_HASH_REGS_OFFSET + 0x18)
#define STARFIVE_HASH_SHAWLEN0			(STARFIVE_HASH_REGS_OFFSET + 0x1C)
#define STARFIVE_HASH_SHAWKR			(STARFIVE_HASH_REGS_OFFSET + 0x20)
#define STARFIVE_HASH_SHAWKLEN			(STARFIVE_HASH_REGS_OFFSET + 0x24)

union starfive_hash_csr {
	u32 v;
	struct {
		u32 start			:1;
		u32 reset			:1;
		u32 rsvd_0			:1;
		u32 firstb			:1;
#define STARFIVE_HASH_SM3			0x0
#define STARFIVE_HASH_SHA224			0x3
#define STARFIVE_HASH_SHA256			0x4
#define STARFIVE_HASH_SHA384			0x5
#define STARFIVE_HASH_SHA512			0x6
#define STARFIVE_HASH_MODE_MASK			0x7
		u32 mode			:3;
		u32 rsvd_1			:1;
		u32 final			:1;
		u32 rsvd_2			:2;
#define STARFIVE_HASH_HMAC_FLAGS		0x800
		u32 hmac			:1;
		u32 rsvd_3			:1;
#define STARFIVE_HASH_KEY_DONE			BIT(13)
		u32 key_done			:1;
		u32 key_flag			:1;
#define STARFIVE_HASH_HMAC_DONE			BIT(15)
		u32 hmac_done			:1;
#define STARFIVE_HASH_BUSY			BIT(16)
		u32 busy			:1;
		u32 hashdone			:1;
		u32 rsvd_4			:14;
	};
};

#endif
