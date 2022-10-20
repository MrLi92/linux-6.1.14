/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __STARFIVE_REGS_H__
#define __STARFIVE_REGS_H__

#define STARFIVE_ALG_CR_OFFSET			0x0
#define STARFIVE_ALG_FIFO_OFFSET		0x4
#define STARFIVE_IE_MASK_OFFSET			0x8
#define STARFIVE_IE_FLAG_OFFSET			0xc
#define STARFIVE_DMA_IN_LEN_OFFSET		0x10
#define STARFIVE_DMA_OUT_LEN_OFFSET		0x14

#define STARFIVE_AES_REGS_OFFSET		0x100
#define STARFIVE_HASH_REGS_OFFSET		0x300
#define STARFIVE_PKA_REGS_OFFSET		0x400

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

#define STARFIVE_PKA_CACR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x0)
#define STARFIVE_PKA_CASR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x4)
#define STARFIVE_PKA_CAAR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x8)
#define STARFIVE_PKA_CAER_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x108)
#define STARFIVE_PKA_CANR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x208)
#define STARFIVE_PKA_CAAFR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x308)
#define STARFIVE_PKA_CAEFR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x30c)
#define STARFIVE_PKA_CANFR_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x310)
#define STARFIVE_FIFO_COUNTER_OFFSET		(STARFIVE_PKA_REGS_OFFSET + 0x314)

/* R^2 mod N and N0' */
#define CRYPTO_CMD_PRE				0x0
/* (A + A) mod N, ==> A */
#define CRYPTO_CMD_AAN				0x1
/* A ^ E mod N   ==> A */
#define CRYPTO_CMD_AMEN				0x2
/* A + E mod N   ==> A */
#define CRYPTO_CMD_AAEN				0x3
/* A - E mod N   ==> A */
#define CRYPTO_CMD_ADEN				0x4
/* A * R mod N   ==> A */
#define CRYPTO_CMD_ARN				0x5
/* A * E * R mod N ==> A */
#define CRYPTO_CMD_AERN				0x6
/* A * A * R mod N ==> A */
#define CRYPTO_CMD_AARN				0x7
/* ECC2P      ==> A */
#define CRYPTO_CMD_ECC2P			0x8
/* ECCPQ      ==> A */
#define CRYPTO_CMD_ECCPQ			0x9

union starfive_pka_cacr {
	u32 v;
	struct {
		u32 start			:1;
		u32 reset                       :1;
		u32 ie                          :1;
		u32 rsvd_0                      :1;
		u32 fifo_mode                   :1;
		u32 not_r2                      :1;
		u32 ecc_sub                     :1;
		u32 pre_expf                    :1;
		u32 cmd                         :4;
		u32 rsvd_1                      :1;
		u32 ctrl_dummy                  :1;
		u32 ctrl_false                  :1;
		u32 cln_done                    :1;
		u32 opsize                      :6;
		u32 rsvd_2                      :2;
		u32 exposize                    :6;
		u32 rsvd_3                      :1;
		u32 bigendian                   :1;
	};
};

union starfive_pka_casr {
	u32 v;
	struct {
#define STARFIVE_PKA_DONE_FLAGS			BIT(0)
		u32 done                        :1;
		u32 rsvd_0                      :31;
	};
};

#define STARFIVE_AES_AESDIO0R			(STARFIVE_AES_REGS_OFFSET + 0x0)
#define STARFIVE_AES_KEY0			(STARFIVE_AES_REGS_OFFSET + 0x4)
#define STARFIVE_AES_KEY1			(STARFIVE_AES_REGS_OFFSET + 0x8)
#define STARFIVE_AES_KEY2			(STARFIVE_AES_REGS_OFFSET + 0xC)
#define STARFIVE_AES_KEY3			(STARFIVE_AES_REGS_OFFSET + 0x10)
#define STARFIVE_AES_KEY4			(STARFIVE_AES_REGS_OFFSET + 0x14)
#define STARFIVE_AES_KEY5			(STARFIVE_AES_REGS_OFFSET + 0x18)
#define STARFIVE_AES_KEY6			(STARFIVE_AES_REGS_OFFSET + 0x1C)
#define STARFIVE_AES_KEY7			(STARFIVE_AES_REGS_OFFSET + 0x20)
#define STARFIVE_AES_CSR			(STARFIVE_AES_REGS_OFFSET + 0x24)
#define STARFIVE_AES_IV0			(STARFIVE_AES_REGS_OFFSET + 0x28)
#define STARFIVE_AES_IV1			(STARFIVE_AES_REGS_OFFSET + 0x2C)
#define STARFIVE_AES_IV2			(STARFIVE_AES_REGS_OFFSET + 0x30)
#define STARFIVE_AES_IV3			(STARFIVE_AES_REGS_OFFSET + 0x34)
#define STARFIVE_AES_NONCE0			(STARFIVE_AES_REGS_OFFSET + 0x3C)
#define STARFIVE_AES_NONCE1			(STARFIVE_AES_REGS_OFFSET + 0x40)
#define STARFIVE_AES_NONCE2			(STARFIVE_AES_REGS_OFFSET + 0x44)
#define STARFIVE_AES_NONCE3			(STARFIVE_AES_REGS_OFFSET + 0x48)
#define STARFIVE_AES_ALEN0			(STARFIVE_AES_REGS_OFFSET + 0x4C)
#define STARFIVE_AES_ALEN1			(STARFIVE_AES_REGS_OFFSET + 0x50)
#define STARFIVE_AES_MLEN0			(STARFIVE_AES_REGS_OFFSET + 0x54)
#define STARFIVE_AES_MLEN1			(STARFIVE_AES_REGS_OFFSET + 0x58)
#define STARFIVE_AES_IVLEN			(STARFIVE_AES_REGS_OFFSET + 0x5C)

union starfive_aes_csr {
	u32 v;
	struct {
		u32 cmode			:1;
#define STARFIVE_AES_KEYMODE_128		0x0
#define STARFIVE_AES_KEYMODE_192		0x1
#define STARFIVE_AES_KEYMODE_256		0x2
		u32 keymode			:2;
#define STARFIVE_AES_BUSY			BIT(3)
		u32 busy			:1;
		u32 done			:1;
#define STARFIVE_AES_KEY_DONE			BIT(5)
		u32 krdy			:1;
		u32 aesrst			:1;
		u32 rsvd_0			:1;
#define STARFIVE_AES_CCM_START			BIT(8)
		u32 ccm_start			:1;
#define STARFIVE_AES_MODE_ECB			0x0
#define STARFIVE_AES_MODE_CBC			0x1
#define STARFIVE_AES_MODE_CFB			0x2
#define STARFIVE_AES_MODE_OFB			0x3
#define STARFIVE_AES_MODE_CTR			0x4
#define STARFIVE_AES_MODE_CCM			0x5
#define STARFIVE_AES_MODE_GCM			0x6
		u32 mode			:3;
#define STARFIVE_AES_GCM_START			BIT(12)
		u32 gcm_start			:1;
#define STARFIVE_AES_GCM_DONE			BIT(13)
		u32 gcm_done			:1;
		u32 delay_aes			:1;
		u32 vaes_start			:1;
		u32 rsvd_1			:8;
#define STARFIVE_AES_MODE_XFB_1			0x0
#define STARFIVE_AES_MODE_XFB_128		0x5
		u32 stream_mode			:3;
		u32 rsvd_2			:5;
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
