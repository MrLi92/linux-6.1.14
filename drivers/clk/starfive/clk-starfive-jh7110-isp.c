// SPDX-License-Identifier: GPL-2.0
/*
 * StarFive JH7110 Image-Signal-Process Clock Driver
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
#define JH7110_ISPCLK_ISP_TOP_CORE		(JH7110_ISPCLK_END + 0)
#define JH7110_ISPCLK_ISP_TOP_AXI		(JH7110_ISPCLK_END + 1)
#define JH7110_ISPCLK_NOC_BUS_ISP_AXI		(JH7110_ISPCLK_END + 2)
#define JH7110_ISPCLK_DVP_CLK			(JH7110_ISPCLK_END + 3)

static const struct jh71x0_clk_data jh7110_ispclk_data[] = {
	/* syscon */
	JH71X0__DIV(JH7110_ISPCLK_DOM4_APB_FUNC, "dom4_apb_func", 15,
		    JH7110_ISPCLK_ISP_TOP_AXI),
	JH71X0__DIV(JH7110_ISPCLK_MIPI_RX0_PXL, "mipi_rx0_pxl", 8,
		    JH7110_ISPCLK_ISP_TOP_CORE),
	JH71X0__INV(JH7110_ISPCLK_DVP_INV, "dvp_inv", JH7110_ISPCLK_DVP_CLK),
	/* vin */
	JH71X0__DIV(JH7110_ISPCLK_M31DPHY_CFGCLK_IN, "m31dphy_cfgclk_in", 16,
		    JH7110_ISPCLK_ISP_TOP_CORE),
	JH71X0__DIV(JH7110_ISPCLK_M31DPHY_REFCLK_IN, "m31dphy_refclk_in", 16,
		    JH7110_ISPCLK_ISP_TOP_CORE),
	JH71X0__DIV(JH7110_ISPCLK_M31DPHY_TXCLKESC_LAN0, "m31dphy_txclkesc_lan0", 60,
		    JH7110_ISPCLK_ISP_TOP_CORE),
	JH71X0_GATE(JH7110_ISPCLK_VIN_PCLK, "vin_pclk", CLK_IGNORE_UNUSED,
		    JH7110_ISPCLK_DOM4_APB_FUNC),
	JH71X0__DIV(JH7110_ISPCLK_VIN_SYS_CLK, "vin_sys_clk", 8, JH7110_ISPCLK_ISP_TOP_CORE),
	JH71X0_GATE(JH7110_ISPCLK_VIN_PIXEL_CLK_IF0, "vin_pixel_clk_if0", CLK_IGNORE_UNUSED,
		    JH7110_ISPCLK_MIPI_RX0_PXL),
	JH71X0_GATE(JH7110_ISPCLK_VIN_PIXEL_CLK_IF1, "vin_pixel_clk_if1", CLK_IGNORE_UNUSED,
		    JH7110_ISPCLK_MIPI_RX0_PXL),
	JH71X0_GATE(JH7110_ISPCLK_VIN_PIXEL_CLK_IF2, "vin_pixel_clk_if2", CLK_IGNORE_UNUSED,
		    JH7110_ISPCLK_MIPI_RX0_PXL),
	JH71X0_GATE(JH7110_ISPCLK_VIN_PIXEL_CLK_IF3, "vin_pixel_clk_if3", CLK_IGNORE_UNUSED,
		    JH7110_ISPCLK_MIPI_RX0_PXL),
	JH71X0__MUX(JH7110_ISPCLK_VIN_CLK_P_AXIWR, "vin_clk_p_axiwr", 2,
		    JH7110_ISPCLK_MIPI_RX0_PXL,
		    JH7110_ISPCLK_DVP_INV),
	/* ispv2_top_wrapper */
	JH71X0_GMUX(JH7110_ISPCLK_ISPV2_TOP_WRAPPER_CLK_C, "ispv2_top_wrapper_clk_c",
		    CLK_IGNORE_UNUSED, 2,
		    JH7110_ISPCLK_MIPI_RX0_PXL,
		    JH7110_ISPCLK_DVP_INV),
};

struct isp_top_crg {
	struct clk_bulk_data *top_clks;
	struct reset_control *top_rsts;
	int top_clks_num;
};

static struct clk_bulk_data jh7110_isp_top_clks[] = {
	{ .id = "isp_top_core" },
	{ .id = "isp_top_axi" }
};

static int jh7110_isp_top_crg_get(struct jh71x0_clk_priv *priv, struct isp_top_crg *top)
{
	int ret;

	top->top_clks = jh7110_isp_top_clks;
	top->top_clks_num = ARRAY_SIZE(jh7110_isp_top_clks);
	ret = devm_clk_bulk_get(priv->dev, top->top_clks_num, top->top_clks);
	if (ret) {
		dev_err(priv->dev, "top clks get failed: %d\n", ret);
		return ret;
	}

	/* The resets should be shared and other ISP modules will use its. */
	top->top_rsts = devm_reset_control_array_get_shared(priv->dev);
	if (IS_ERR(top->top_rsts)) {
		dev_err(priv->dev, "top rsts get failed\n");
		return PTR_ERR(top->top_rsts);
	}

	return 0;
}

static int jh7110_isp_top_crg_enable(struct isp_top_crg *top)
{
	int ret;

	ret = clk_bulk_prepare_enable(top->top_clks_num, top->top_clks);
	if (ret)
		return ret;

	return reset_control_deassert(top->top_rsts);
}

static struct clk_hw *jh7110_ispclk_get(struct of_phandle_args *clkspec, void *data)
{
	struct jh71x0_clk_priv *priv = data;
	unsigned int idx = clkspec->args[0];

	if (idx < JH7110_ISPCLK_END)
		return &priv->reg[idx].hw;

	return ERR_PTR(-EINVAL);
}

static int jh7110_ispcrg_probe(struct platform_device *pdev)
{
	struct jh71x0_clk_priv *priv;
	struct isp_top_crg *top;
	unsigned int idx;
	int ret;

	priv = devm_kzalloc(&pdev->dev,
			    struct_size(priv, reg, JH7110_ISPCLK_END),
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

	ret = jh7110_isp_top_crg_get(priv, top);
	if (ret)
		return ret;

	ret = jh7110_isp_top_crg_enable(top);
	if (ret)
		return ret;

	for (idx = 0; idx < JH7110_ISPCLK_END; idx++) {
		u32 max = jh7110_ispclk_data[idx].max;
		struct clk_parent_data parents[4] = {};
		struct clk_init_data init = {
			.name = jh7110_ispclk_data[idx].name,
			.ops = starfive_jh71x0_clk_ops(max),
			.parent_data = parents,
			.num_parents =
				((max & JH71X0_CLK_MUX_MASK) >> JH71X0_CLK_MUX_SHIFT) + 1,
			.flags = jh7110_ispclk_data[idx].flags,
		};
		struct jh71x0_clk *clk = &priv->reg[idx];
		unsigned int i;

		for (i = 0; i < init.num_parents; i++) {
			unsigned int pidx = jh7110_ispclk_data[idx].parents[i];

			if (pidx < JH7110_ISPCLK_END)
				parents[i].hw = &priv->reg[pidx].hw;
			else if (pidx == JH7110_ISPCLK_ISP_TOP_CORE)
				parents[i].fw_name = "isp_top_core";
			else if (pidx == JH7110_ISPCLK_ISP_TOP_AXI)
				parents[i].fw_name = "isp_top_axi";
			else if (pidx == JH7110_ISPCLK_NOC_BUS_ISP_AXI)
				parents[i].fw_name = "noc_bus_isp_axi";
			else if (pidx == JH7110_ISPCLK_DVP_CLK)
				parents[i].fw_name = "dvp_clk";
		}

		clk->hw.init = &init;
		clk->idx = idx;
		clk->max_div = max & JH71X0_CLK_DIV_MASK;

		ret = devm_clk_hw_register(&pdev->dev, &clk->hw);
		if (ret)
			return ret;
	}

	ret = devm_of_clk_add_hw_provider(&pdev->dev, jh7110_ispclk_get, priv);
	if (ret)
		return ret;

	return jh7110_reset_controller_register(priv, "reset-isp", 3);
}

static const struct of_device_id jh7110_ispcrg_match[] = {
	{ .compatible = "starfive,jh7110-ispcrg" },
	{ /* sentinel */ }
};
MODULE_DEVICE_TABLE(of, jh7110_ispcrg_match);

static struct platform_driver jh7110_ispcrg_driver = {
	.probe = jh7110_ispcrg_probe,
	.driver = {
		.name = "clk-starfive-jh7110-isp",
		.of_match_table = jh7110_ispcrg_match,
	},
};
module_platform_driver(jh7110_ispcrg_driver);

MODULE_AUTHOR("Xingyu Wu <xingyu.wu@starfivetech.com>");
MODULE_DESCRIPTION("StarFive JH7110 Image-Signal-Process clock driver");
MODULE_LICENSE("GPL");
