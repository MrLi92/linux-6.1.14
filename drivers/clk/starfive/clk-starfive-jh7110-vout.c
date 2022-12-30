// SPDX-License-Identifier: GPL-2.0
/*
 * StarFive JH7110 Video-Output Clock Driver
 *
 * Copyright (C) 2022 StarFive Technology Co., Ltd.
 */

#include <linux/clk.h>
#include <linux/clk-provider.h>
#include <linux/io.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>

#include <dt-bindings/clock/starfive,jh7110-crg.h>

#include "clk-starfive-jh71x0.h"

/* external clocks */
#define JH7110_VOUTCLK_VOUT_SRC			(JH7110_VOUTCLK_END + 0)
#define JH7110_VOUTCLK_VOUT_TOP_AHB		(JH7110_VOUTCLK_END + 1)
#define JH7110_VOUTCLK_VOUT_TOP_AXI		(JH7110_VOUTCLK_END + 2)
#define JH7110_VOUTCLK_VOUT_TOP_HDMITX0_MCLK	(JH7110_VOUTCLK_END + 3)
#define JH7110_VOUTCLK_I2STX0_BCLK		(JH7110_VOUTCLK_END + 4)
#define JH7110_VOUTCLK_HDMITX0_PIXELCLK		(JH7110_VOUTCLK_END + 5)

static const struct jh71x0_clk_data jh7110_voutclk_data[] = {
	/* divider */
	JH71X0__DIV(JH7110_VOUTCLK_APB, "apb", 8, JH7110_VOUTCLK_VOUT_TOP_AHB),
	JH71X0__DIV(JH7110_VOUTCLK_DC8200_PIX, "dc8200_pix", 63, JH7110_VOUTCLK_VOUT_SRC),
	JH71X0__DIV(JH7110_VOUTCLK_DSI_SYS, "dsi_sys", 31, JH7110_VOUTCLK_VOUT_SRC),
	JH71X0__DIV(JH7110_VOUTCLK_TX_ESC, "tx_esc", 31, JH7110_VOUTCLK_VOUT_TOP_AHB),
	/* dc8200 */
	JH71X0_GATE(JH7110_VOUTCLK_DC8200_AXI, "dc8200_axi", 0, JH7110_VOUTCLK_VOUT_TOP_AXI),
	JH71X0_GATE(JH7110_VOUTCLK_DC8200_CORE, "dc8200_core", 0, JH7110_VOUTCLK_VOUT_TOP_AXI),
	JH71X0_GATE(JH7110_VOUTCLK_DC8200_AHB, "dc8200_ahb", 0, JH7110_VOUTCLK_VOUT_TOP_AHB),
	JH71X0_GMUX(JH7110_VOUTCLK_DC8200_PIX0, "dc8200_pix0", 0, 2,
		    JH7110_VOUTCLK_DC8200_PIX,
		    JH7110_VOUTCLK_HDMITX0_PIXELCLK),
	JH71X0_GMUX(JH7110_VOUTCLK_DC8200_PIX1, "dc8200_pix1", 0, 2,
		    JH7110_VOUTCLK_DC8200_PIX,
		    JH7110_VOUTCLK_HDMITX0_PIXELCLK),
	/* LCD */
	JH71X0_GMUX(JH7110_VOUTCLK_DOM_VOUT_TOP_LCD, "dom_vout_top_lcd", 0, 2,
		    JH7110_VOUTCLK_DC8200_PIX0,
		    JH7110_VOUTCLK_DC8200_PIX1),
	/* dsiTx */
	JH71X0_GATE(JH7110_VOUTCLK_DSITX_APB, "dsiTx_apb", 0, JH7110_VOUTCLK_DSI_SYS),
	JH71X0_GATE(JH7110_VOUTCLK_DSITX_SYS, "dsiTx_sys", 0, JH7110_VOUTCLK_DSI_SYS),
	JH71X0_GMUX(JH7110_VOUTCLK_DSITX_DPI, "dsiTx_dpi", 0, 2,
		    JH7110_VOUTCLK_DC8200_PIX,
		    JH7110_VOUTCLK_HDMITX0_PIXELCLK),
	JH71X0_GATE(JH7110_VOUTCLK_DSITX_TXESC, "dsiTx_txesc", 0, JH7110_VOUTCLK_TX_ESC),
	/* mipitx DPHY */
	JH71X0_GATE(JH7110_VOUTCLK_MIPITX_DPHY_TXESC, "mipitx_dphy_txesc", 0,
		    JH7110_VOUTCLK_TX_ESC),
	/* hdmi */
	JH71X0_GATE(JH7110_VOUTCLK_HDMI_TX_MCLK, "hdmi_tx_mclk", 0,
		    JH7110_VOUTCLK_VOUT_TOP_HDMITX0_MCLK),
	JH71X0_GATE(JH7110_VOUTCLK_HDMI_TX_BCLK, "hdmi_tx_bclk", 0,
		    JH7110_VOUTCLK_I2STX0_BCLK),
	JH71X0_GATE(JH7110_VOUTCLK_HDMI_TX_SYS, "hdmi_tx_sys", 0, JH7110_VOUTCLK_APB),
};

struct vout_top_crg {
	struct clk_bulk_data *top_clks;
	struct reset_control *top_rst;
	int top_clks_num;
};

static struct clk_bulk_data jh7110_vout_top_clks[] = {
	{ .id = "vout_src" },
	{ .id = "vout_top_ahb" }
};

static int jh7110_vout_top_crg_get(struct jh71x0_clk_priv *priv, struct vout_top_crg *top)
{
	int ret;

	top->top_clks = jh7110_vout_top_clks;
	top->top_clks_num = ARRAY_SIZE(jh7110_vout_top_clks);
	ret = devm_clk_bulk_get(priv->dev, top->top_clks_num, top->top_clks);
	if (ret) {
		dev_err(priv->dev, "top clks get failed: %d\n", ret);
		return ret;
	}

	/* The reset should be shared and other Vout modules will use its. */
	top->top_rst = devm_reset_control_get_shared(priv->dev, NULL);
	if (IS_ERR(top->top_rst)) {
		dev_err(priv->dev, "top rst get failed\n");
		return PTR_ERR(top->top_rst);
	}

	return 0;
}

static int jh7110_vout_top_crg_enable(struct vout_top_crg *top)
{
	int ret;

	ret = clk_bulk_prepare_enable(top->top_clks_num, top->top_clks);
	if (ret)
		return ret;

	return reset_control_deassert(top->top_rst);
}

static struct clk_hw *jh7110_voutclk_get(struct of_phandle_args *clkspec, void *data)
{
	struct jh71x0_clk_priv *priv = data;
	unsigned int idx = clkspec->args[0];

	if (idx < JH7110_VOUTCLK_END)
		return &priv->reg[idx].hw;

	return ERR_PTR(-EINVAL);
}

static int jh7110_voutcrg_probe(struct platform_device *pdev)
{
	struct jh71x0_clk_priv *priv;
	struct vout_top_crg *top;
	unsigned int idx;
	int ret;

	priv = devm_kzalloc(&pdev->dev,
			    struct_size(priv, reg, JH7110_VOUTCLK_END),
			    GFP_KERNEL);
	if (!priv)
		return -ENOMEM;

	top = devm_kzalloc(&pdev->dev, sizeof(*top), GFP_KERNEL);
	if (!top)
		return -ENOMEM;

	spin_lock_init(&priv->rmw_lock);
	priv->dev = &pdev->dev;
	priv->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(priv->base))
		return PTR_ERR(priv->base);

	dev_set_drvdata(priv->dev, priv->base);

	pm_runtime_enable(priv->dev);
	ret = pm_runtime_get_sync(priv->dev);
	if (ret < 0) {
		dev_err(priv->dev, "failed to turn power: %d\n", ret);
		return ret;
	}

	ret = jh7110_vout_top_crg_get(priv, top);
	if (ret)
		return ret;

	ret = jh7110_vout_top_crg_enable(top);
	if (ret)
		return ret;

	for (idx = 0; idx < JH7110_VOUTCLK_END; idx++) {
		u32 max = jh7110_voutclk_data[idx].max;
		struct clk_parent_data parents[4] = {};
		struct clk_init_data init = {
			.name = jh7110_voutclk_data[idx].name,
			.ops = starfive_jh71x0_clk_ops(max),
			.parent_data = parents,
			.num_parents =
				((max & JH71X0_CLK_MUX_MASK) >> JH71X0_CLK_MUX_SHIFT) + 1,
			.flags = jh7110_voutclk_data[idx].flags,
		};
		struct jh71x0_clk *clk = &priv->reg[idx];
		unsigned int i;

		for (i = 0; i < init.num_parents; i++) {
			unsigned int pidx = jh7110_voutclk_data[idx].parents[i];

			if (pidx < JH7110_VOUTCLK_END)
				parents[i].hw = &priv->reg[pidx].hw;
			else if (pidx == JH7110_VOUTCLK_VOUT_SRC)
				parents[i].fw_name = "vout_src";
			else if (pidx == JH7110_VOUTCLK_VOUT_TOP_AHB)
				parents[i].fw_name = "vout_top_ahb";
			else if (pidx == JH7110_VOUTCLK_VOUT_TOP_AXI)
				parents[i].fw_name = "vout_top_axi";
			else if (pidx == JH7110_VOUTCLK_VOUT_TOP_HDMITX0_MCLK)
				parents[i].fw_name = "vout_top_hdmitx0_mclk";
			else if (pidx == JH7110_VOUTCLK_I2STX0_BCLK)
				parents[i].fw_name = "i2stx0_bclk";
			else if (pidx == JH7110_VOUTCLK_HDMITX0_PIXELCLK)
				parents[i].fw_name = "hdmitx0_pixelclk";
		}

		clk->hw.init = &init;
		clk->idx = idx;
		clk->max_div = max & JH71X0_CLK_DIV_MASK;

		ret = devm_clk_hw_register(&pdev->dev, &clk->hw);
		if (ret)
			return ret;
	}

	ret = devm_of_clk_add_hw_provider(&pdev->dev, jh7110_voutclk_get, priv);
	if (ret)
		return ret;

	return jh7110_reset_controller_register(priv, "reset-vout", 4);
}

static const struct of_device_id jh7110_voutcrg_match[] = {
	{ .compatible = "starfive,jh7110-voutcrg" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, jh7110_voutcrg_match);

static struct platform_driver jh7110_voutcrg_driver = {
	.probe = jh7110_voutcrg_probe,
	.driver = {
		.name = "clk-starfive-jh7110-vout",
		.of_match_table = jh7110_voutcrg_match,
	},
};
module_platform_driver(jh7110_voutcrg_driver);

MODULE_AUTHOR("Xingyu Wu <xingyu.wu@starfivetech.com>");
MODULE_DESCRIPTION("StarFive JH7110 Video-Output clock driver");
MODULE_LICENSE("GPL");
