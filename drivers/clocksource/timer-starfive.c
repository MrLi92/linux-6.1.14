// SPDX-License-Identifier: GPL-2.0
/*
 * Starfive Timer driver
 *
 * Copyright (C) 2022 StarFive Technology Co., Ltd.
 *
 * Author:
 * Xingyu Wu <xingyu.wu@starfivetech.com>
 * Samin Guo <samin.guo@starfivetech.com>
 */

#include <linux/clk.h>
#include <linux/clockchips.h>
#include <linux/clocksource.h>
#include <linux/err.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/iopoll.h>
#include <linux/irq.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_clk.h>
#include <linux/of_irq.h>
#include <linux/reset.h>
#include <linux/sched_clock.h>

#include "timer-starfive.h"

struct starfive_timer __initdata starfive_timer_jh7110 = {
	.ctrl		= STARFIVE_TIMER_JH7110_CTL,
	.load		= STARFIVE_TIMER_JH7110_LOAD,
	.enable		= STARFIVE_TIMER_JH7110_ENABLE,
	.reload		= STARFIVE_TIMER_JH7110_RELOAD,
	.value		= STARFIVE_TIMER_JH7110_VALUE,
	.intclr		= STARFIVE_TIMER_JH7110_INT_CLR,
	.intmask	= STARFIVE_TIMER_JH7110_INT_MASK,
	.timer_base	= {STARFIVE_TIMER_BASE(0), STARFIVE_TIMER_BASE(1),
			   STARFIVE_TIMER_BASE(2), STARFIVE_TIMER_BASE(3)},
};

static inline struct starfive_clkevt *to_starfive_clkevt(struct clock_event_device *evt)
{
	return container_of(evt, struct starfive_clkevt, evt);
}

/* 0:continuous-run mode, 1:single-run mode */
static inline void starfive_timer_set_mod(struct starfive_clkevt *clkevt, int mod)
{
	writel(mod, clkevt->ctrl);
}

/* Interrupt Mask Register, 0:Unmask, 1:Mask */
static inline void starfive_timer_int_enable(struct starfive_clkevt *clkevt)
{
	writel(INTMASK_ENABLE_DIS, clkevt->intmask);
}

static inline void starfive_timer_int_disable(struct starfive_clkevt *clkevt)
{
	writel(INTMASK_ENABLE, clkevt->intmask);
}

/*
 * BIT(0): Read value represent channel intr status.
 * Write 1 to this bit to clear interrupt. Write 0 has no effects.
 * BIT(1): "1" means that it is clearing interrupt. BIT(0) can not be written.
 */
static inline void starfive_timer_int_clear(struct starfive_clkevt *clkevt)
{
	/* waiting interrupt can be to clearing */
	u32 value;
	int ret = 0;

	value = readl(clkevt->intclr);
	ret = readl_poll_timeout_atomic(clkevt->intclr, value,
					!(value & STARFIVE_TIMER_JH7110_INT_STATUS_CLR_AVA),
					STARFIVE_DELAY_US, STARFIVE_TIMEOUT_US);
	if (!ret)
		writel(1, clkevt->intclr);
}

/*
 * The initial value to be loaded into the
 * counter and is also used as the reload value.
 */
static inline void starfive_timer_set_load(struct starfive_clkevt *clkevt, u32 val)
{
	writel(val, clkevt->load);
}

static inline u32 starfive_timer_get_val(struct starfive_clkevt *clkevt)
{
	return readl(clkevt->value);
}

/*
 * Write RELOAD register to reload preset value to counter.
 * (Write 0 and write 1 are both ok)
 */
static inline void starfive_timer_set_reload(struct starfive_clkevt *clkevt)
{
	writel(1, clkevt->reload);
}

static inline void starfive_timer_enable(struct starfive_clkevt *clkevt)
{
	writel(TIMER_ENA, clkevt->enable);
}

static inline void starfive_timer_disable(struct starfive_clkevt *clkevt)
{
	writel(TIMER_ENA_DIS, clkevt->enable);
}

static void timer_shutdown(struct starfive_clkevt *clkevt)
{
	starfive_timer_int_disable(clkevt);
	starfive_timer_disable(clkevt);
	starfive_timer_int_clear(clkevt);
}

static void starfive_timer_suspend(struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	clkevt->reload_val = starfive_timer_get_val(clkevt);

	starfive_timer_disable(clkevt);
	starfive_timer_int_disable(clkevt);
	starfive_timer_int_clear(clkevt);
}

static void starfive_timer_resume(struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	starfive_timer_set_load(clkevt, clkevt->reload_val);
	starfive_timer_set_reload(clkevt);
	starfive_timer_int_enable(clkevt);
	starfive_timer_enable(clkevt);
}

static int starfive_timer_tick_resume(struct clock_event_device *evt)
{
	starfive_timer_resume(evt);

	return 0;
}

static int starfive_timer_shutdown(struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	timer_shutdown(clkevt);

	return 0;
}

static int starfive_get_clock_rate(struct starfive_clkevt *clkevt, struct device_node *np)
{
	int ret;
	u32 rate;

	if (clkevt->clk) {
		clkevt->rate = clk_get_rate(clkevt->clk);
		if (clkevt->rate > 0) {
			pr_debug("clk_get_rate clkevt->rate: %d\n", clkevt->rate);
			return 0;
		}
	}

	/* Next we try to get clock-frequency from dts.*/
	ret = of_property_read_u32(np, "clock-frequency", &rate);
	if (!ret) {
		pr_debug("Timer: try get clock-frequency:%d Hz\n", rate);
		clkevt->rate = rate;
		return 0;
	}
	pr_err("Timer: get rate failed, need clock-frequency define in dts.\n");

	return -ENOENT;
}

static int starfive_clocksource_init(struct starfive_clkevt *clkevt,
				     const char *name, struct device_node *np)
{
	starfive_timer_set_mod(clkevt, MOD_CONTIN);
	starfive_timer_set_load(clkevt, STARFIVE_MAX_TICKS);  /* val = rate --> 1s */
	starfive_timer_int_disable(clkevt);
	starfive_timer_int_clear(clkevt);
	starfive_timer_int_enable(clkevt);
	starfive_timer_enable(clkevt);

	return clocksource_mmio_init(clkevt->value, name, clkevt->rate,
				     STARFIVE_CLOCK_SOURCE_RATING, STARFIVE_VALID_BITS,
				     clocksource_mmio_readl_down);
}

/*
 * IRQ handler for the timer
 */
static irqreturn_t starfive_timer_interrupt(int irq, void *priv)
{
	struct clock_event_device *evt = (struct clock_event_device *)priv;
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	starfive_timer_int_clear(clkevt);

	if (evt->event_handler)
		evt->event_handler(evt);

	return IRQ_HANDLED;
}

static int starfive_timer_set_periodic(struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	starfive_timer_disable(clkevt);
	starfive_timer_set_mod(clkevt, MOD_CONTIN);
	starfive_timer_set_load(clkevt, clkevt->periodic);
	starfive_timer_int_disable(clkevt);
	starfive_timer_int_clear(clkevt);
	starfive_timer_int_enable(clkevt);
	starfive_timer_enable(clkevt);

	return 0;
}

static int starfive_timer_set_oneshot(struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	starfive_timer_disable(clkevt);
	starfive_timer_set_mod(clkevt, MOD_SINGLE);
	starfive_timer_set_load(clkevt, STARFIVE_MAX_TICKS);
	starfive_timer_int_disable(clkevt);
	starfive_timer_int_clear(clkevt);
	starfive_timer_int_enable(clkevt);
	starfive_timer_enable(clkevt);

	return 0;
}

static int starfive_timer_set_next_event(unsigned long next,
					 struct clock_event_device *evt)
{
	struct starfive_clkevt *clkevt = to_starfive_clkevt(evt);

	starfive_timer_disable(clkevt);
	starfive_timer_set_mod(clkevt, MOD_SINGLE);
	starfive_timer_set_load(clkevt, next);
	starfive_timer_enable(clkevt);

	return 0;
}

static void starfive_set_clockevent(struct clock_event_device *evt)
{
	evt->features	= CLOCK_EVT_FEAT_PERIODIC |
			  CLOCK_EVT_FEAT_ONESHOT |
			  CLOCK_EVT_FEAT_DYNIRQ;
	evt->set_state_shutdown	= starfive_timer_shutdown;
	evt->set_state_periodic	= starfive_timer_set_periodic;
	evt->set_state_oneshot	= starfive_timer_set_oneshot;
	evt->set_state_oneshot_stopped = starfive_timer_shutdown;
	evt->tick_resume	= starfive_timer_tick_resume;
	evt->set_next_event	= starfive_timer_set_next_event;
	evt->suspend		= starfive_timer_suspend;
	evt->resume		= starfive_timer_resume;
	evt->rating		= STARFIVE_CLOCKEVENT_RATING;
}

static int starfive_clockevents_register(struct starfive_clkevt *clkevt, unsigned int irq,
					 struct device_node *np, const char *name)
{
	int ret = 0;

	ret = starfive_get_clock_rate(clkevt, np);
	if (ret)
		return -EINVAL;

	clkevt->periodic = DIV_ROUND_CLOSEST(clkevt->rate, HZ);

	starfive_set_clockevent(&clkevt->evt);
	clkevt->evt.name = name;
	clkevt->evt.irq = irq;
	clkevt->evt.cpumask = cpu_possible_mask;

	ret = request_irq(irq, starfive_timer_interrupt,
			  IRQF_TIMER | IRQF_IRQPOLL, name, &clkevt->evt);
	if (ret)
		pr_err("%s: request_irq failed\n", name);

	clockevents_config_and_register(&clkevt->evt, clkevt->rate,
					STARFIVE_MIN_TICKS, STARFIVE_MAX_TICKS);

	return ret;
}

static void __init starfive_clkevt_base_init(struct starfive_timer *timer,
					     struct starfive_clkevt *clkevt,
					     void __iomem *base, int index)
{
	void __iomem *timer_base;

	timer_base	= base + timer->timer_base[index];
	clkevt->base	= timer_base;
	clkevt->ctrl	= timer_base + timer->ctrl;
	clkevt->load	= timer_base + timer->load;
	clkevt->enable	= timer_base + timer->enable;
	clkevt->reload	= timer_base + timer->reload;
	clkevt->value	= timer_base + timer->value;
	clkevt->intclr	= timer_base + timer->intclr;
	clkevt->intmask	= timer_base + timer->intmask;
}

static int __init starfive_timer_jh7110_of_init(struct device_node *np)
{
	int index, count, irq, ret;
	const char *name = NULL;
	struct clk *clk;
	struct clk *pclk;
	struct reset_control *prst;
	struct reset_control *rst;
	struct starfive_clkevt *clkevt[STARFIVE_NR_TIMERS];
	void __iomem *base;
	struct starfive_timer *timer = &starfive_timer_jh7110;

	base = of_iomap(np, 0);
	if (!base)
		return -ENXIO;

	if (!of_device_is_available(np)) {
		ret = -EINVAL;
		goto err;
	}

	pclk = of_clk_get_by_name(np, "apb");
	if (!IS_ERR(pclk)) {
		if (clk_prepare_enable(pclk))
			pr_warn("pclk for %pOFn is present, but could not be activated\n", np);
	/*
	 * Clock framework support is late, continue on
	 * anyways if we don't find a matching clock.
	 */
	} else if (PTR_ERR(pclk) != -EPROBE_DEFER) {
		ret = PTR_ERR(pclk);
		goto err;
	}

	prst = of_reset_control_get(np, "apb");
	if (!IS_ERR(prst)) {
		ret = reset_control_deassert(prst);
		if (ret)
			goto prst_err;
	/*
	 * Reset framework support is late, continue on
	 * anyways if we don't find a matching reset.
	 */
	} else if (PTR_ERR(prst) != -EPROBE_DEFER) {
		ret = PTR_ERR(prst);
		goto prst_err;
	}

	/* The number of timers used is determined according to the device tree. */
	count = of_irq_count(np);
	if (count > STARFIVE_NR_TIMERS || count <= 0) {
		ret = -EINVAL;
		goto count_err;
	}

	for (index = 0; index < count; index++) {
		of_property_read_string_index(np, "clock-names", index, &name);
		if (strncmp(name, "timer", strlen("timer")))
			continue;

		clkevt[index] = kzalloc(sizeof(*clkevt[index]), GFP_KERNEL);
		if (!clkevt[index]) {
			ret = -ENOMEM;
			goto clkevt_err;
		}

		starfive_clkevt_base_init(timer, clkevt[index], base, index);

		/* Ensure timers are disabled */
		starfive_timer_disable(clkevt[index]);

		clk = of_clk_get_by_name(np, name);
		if (!IS_ERR(clk)) {
			clkevt[index]->clk = clk;
			if (clk_prepare_enable(clkevt[index]->clk))
				pr_warn("clk for %pOFn is present, but could not be activated\n",
					np);
		} else if (PTR_ERR(clk) != -EPROBE_DEFER) {
			ret = PTR_ERR(clk);
			goto clk_err;
		}

		rst = of_reset_control_get(np, name);
		if (!IS_ERR(rst)) {
			clkevt[index]->rst = rst;
			ret = reset_control_deassert(clkevt[index]->rst);
			if (ret)
				goto rst_err;
		}

		irq = irq_of_parse_and_map(np, index);
		if (irq < 0) {
			ret = -EINVAL;
			goto irq_err;
		}

		snprintf(clkevt[index]->name, sizeof(clkevt[index]->name), "%s.ch%d",
			 np->full_name, index);

		ret = starfive_clockevents_register(clkevt[index], irq, np, clkevt[index]->name);
		if (ret) {
			pr_err("%s: init clockevents failed.\n", clkevt[index]->name);
			goto register_err;
		}
		clkevt[index]->irq = irq;

		ret = starfive_clocksource_init(clkevt[index], clkevt[index]->name, np);
		if (ret)
			goto init_err;
	}
	if (!IS_ERR(pclk))
		clk_put(pclk);

	return 0;

init_err:
register_err:
	free_irq(clkevt[index]->irq, &clkevt[index]->evt);
irq_err:
rst_err:
clk_err:
	/* Only unregister the failed timer and the rest timers continue to work. */
	if (!clkevt[index]->rst) {
		reset_control_assert(clkevt[index]->rst);
		reset_control_put(clkevt[index]->rst);
	}
	if (!clkevt[index]->clk) {
		clk_disable_unprepare(clkevt[index]->clk);
		clk_put(clkevt[index]->clk);
	}
	kfree(clkevt[index]);
clkevt_err:
count_err:
prst_err:
	if (!IS_ERR(pclk)) {
		/* If no other timer successfully registers, pclk is disabled. */
		if (!index)
			clk_disable_unprepare(pclk);
		clk_put(pclk);
	}
err:
	iounmap(base);
	return ret;
}

TIMER_OF_DECLARE(starfive_timer_jh7110, "starfive,jh7110-timers", starfive_timer_jh7110_of_init);
