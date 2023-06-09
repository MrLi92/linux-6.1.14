// SPDX-License-Identifier: GPL-2.0
/*
 * Starfive Watchdog driver
 *
 * Copyright (C) 2022 StarFive Technology Co., Ltd.
 */

#include <linux/clk.h>
#include <linux/err.h>
#include <linux/iopoll.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/of.h>
#include <linux/of_device.h>
#include <linux/platform_device.h>
#include <linux/pm_runtime.h>
#include <linux/reset.h>
#include <linux/types.h>
#include <linux/watchdog.h>

/* JH7110 WatchDog register define */
#define STARFIVE_WDT_JH7110_LOAD	0x000	/* RW: Watchdog load register */
#define STARFIVE_WDT_JH7110_VALUE	0x004	/* RO: The current value for the watchdog counter */
#define STARFIVE_WDT_JH7110_CONTROL	0x008	/*
						 * RW:
						 * [0]: reset enable;
						 * [1]: int enable/wdt enable/reload counter;
						 * [31:2]: reserve.
						 */
#define STARFIVE_WDT_JH7110_INTCLR	0x00c	/* WO: clear intterupt && reload the counter */
#define STARFIVE_WDT_JH7110_RIS		0x010	/* RO: Raw interrupt status from the counter */
#define STARFIVE_WDT_JH7110_IMS		0x014	/* RO: Enabled interrupt status from the counter */
#define STARFIVE_WDT_JH7110_LOCK	0xc00	/*
						 * RO: Enable write access to all other registers
						 * by writing 0x1ACCE551.
						 */

/* WDOGCONTROL */
#define STARFIVE_WDT_ENABLE			0x1
#define STARFIVE_WDT_JH7110_EN_SHIFT		0
#define STARFIVE_WDT_RESET_EN			0x1
#define STARFIVE_WDT_JH7110_RESEN_SHIFT		1

/* WDOGLOCK */
#define STARFIVE_WDT_LOCKED			BIT(0)
#define STARFIVE_WDT_JH7110_UNLOCK_KEY		0x1acce551

/* WDOGINTCLR */
#define STARFIVE_WDT_INTCLR			0x1

#define STARFIVE_WDT_MAXCNT			0xffffffff
#define STARFIVE_WDT_DEFAULT_TIME		(15)
#define STARFIVE_WDT_DELAY_US			0
#define STARFIVE_WDT_TIMEOUT_US			10000

/* module parameter */
#define STARFIVE_WDT_EARLY_ENA			0

static bool nowayout = WATCHDOG_NOWAYOUT;
static int heartbeat;
static int early_enable = STARFIVE_WDT_EARLY_ENA;

module_param(heartbeat, int, 0);
module_param(early_enable, int, 0);
module_param(nowayout, bool, 0);

MODULE_PARM_DESC(heartbeat, "Watchdog heartbeat in seconds. (default="
		 __MODULE_STRING(STARFIVE_WDT_DEFAULT_TIME) ")");
MODULE_PARM_DESC(early_enable,
		 "Watchdog is started at boot time if set to 1, default="
		 __MODULE_STRING(STARFIVE_WDT_EARLY_ENA));
MODULE_PARM_DESC(nowayout, "Watchdog cannot be stopped once started (default="
		 __MODULE_STRING(WATCHDOG_NOWAYOUT) ")");

struct starfive_wdt_variant {
	u32 control;
	u32 load;
	u32 enable;
	u32 value;
	u32 int_clr;
	u32 unlock;
	u32 unlock_key;
	u32 irq_is_raise;
	u8 enrst_shift;
	u8 en_shift;
};

struct starfive_wdt {
	unsigned long freq;
	struct device *dev;
	struct watchdog_device wdt_device;
	struct clk *core_clk;
	struct clk *apb_clk;
	struct reset_control *rsts;
	const struct starfive_wdt_variant *drv_data;
	u32 count;	/*count of timeout*/
	u32 reload;	/*restore the count*/
	void __iomem *base;
	spinlock_t lock;	/* spinlock for register handling */
};

/* Register bias in JH7110 */
static const struct starfive_wdt_variant drv_data_jh7110 = {
	.control = STARFIVE_WDT_JH7110_CONTROL,
	.load = STARFIVE_WDT_JH7110_LOAD,
	.enable = STARFIVE_WDT_JH7110_CONTROL,
	.value = STARFIVE_WDT_JH7110_VALUE,
	.int_clr = STARFIVE_WDT_JH7110_INTCLR,
	.unlock = STARFIVE_WDT_JH7110_LOCK,
	.unlock_key = STARFIVE_WDT_JH7110_UNLOCK_KEY,
	.irq_is_raise = STARFIVE_WDT_JH7110_IMS,
	.enrst_shift = STARFIVE_WDT_JH7110_RESEN_SHIFT,
	.en_shift = STARFIVE_WDT_JH7110_EN_SHIFT,
};

static const struct of_device_id starfive_wdt_match[] = {
	{ .compatible = "starfive,jh7110-wdt", .data = &drv_data_jh7110 },
	{}
};
MODULE_DEVICE_TABLE(of, starfive_wdt_match);

static const struct platform_device_id starfive_wdt_ids[] = {
	{
		.name = "starfive-jh7110-wdt",
		.driver_data = (unsigned long)&drv_data_jh7110,
	},
	{}
};
MODULE_DEVICE_TABLE(platform, starfive_wdt_ids);

static int starfive_wdt_get_clock_rate(struct starfive_wdt *wdt)
{
	wdt->freq = clk_get_rate(wdt->core_clk);
	/* The clock rate should not be 0.*/
	if (wdt->freq)
		return 0;

	dev_err(wdt->dev, "get clock rate failed.\n");
	return -ENOENT;
}

static int starfive_wdt_get_clock(struct starfive_wdt *wdt)
{
	wdt->apb_clk = devm_clk_get(wdt->dev, "apb");
	if (IS_ERR(wdt->apb_clk)) {
		dev_err(wdt->dev, "failed to get apb clock.\n");
		return PTR_ERR(wdt->apb_clk);
	}

	wdt->core_clk = devm_clk_get(wdt->dev, "core");
	if (IS_ERR(wdt->core_clk)) {
		dev_err(wdt->dev, "failed to get core clock.\n");
		return PTR_ERR(wdt->core_clk);
	}

	return 0;
}

static int starfive_wdt_reset_init(struct starfive_wdt *wdt)
{
	int ret = 0;

	wdt->rsts = devm_reset_control_array_get_exclusive(wdt->dev);
	if (IS_ERR(wdt->rsts)) {
		dev_err(wdt->dev, "failed to get rsts error.\n");
		ret = PTR_ERR(wdt->rsts);
	} else {
		ret = reset_control_deassert(wdt->rsts);
		if (ret)
			dev_err(wdt->dev, "failed to deassert rsts.\n");
	}

	return ret;
}

static u32 starfive_wdt_ticks_to_sec(struct starfive_wdt *wdt, u32 ticks)
{
	return DIV_ROUND_CLOSEST(ticks, wdt->freq);
}

/*
 * Write unlock-key to unlock. Write other value to lock. When lock bit is 1,
 * external accesses to other watchdog registers are ignored.
 */
static bool starfive_wdt_is_locked(struct starfive_wdt *wdt)
{
	u32 val;

	val = readl(wdt->base + wdt->drv_data->unlock);
	return !!(val & STARFIVE_WDT_LOCKED);
}

static void starfive_wdt_unlock(struct starfive_wdt *wdt)
{
	if (starfive_wdt_is_locked(wdt))
		writel(wdt->drv_data->unlock_key,
		       wdt->base + wdt->drv_data->unlock);
}

static void starfive_wdt_lock(struct starfive_wdt *wdt)
{
	if (!starfive_wdt_is_locked(wdt))
		writel(~wdt->drv_data->unlock_key,
		       wdt->base + wdt->drv_data->unlock);
}

/* enable watchdog interrupt to reset/reboot */
static void starfive_wdt_enable_reset(struct starfive_wdt *wdt)
{
	u32 val;

	val = readl(wdt->base + wdt->drv_data->control);
	val |= STARFIVE_WDT_RESET_EN << wdt->drv_data->enrst_shift;
	writel(val, wdt->base + wdt->drv_data->control);
}

/* disable watchdog interrupt to reset/reboot */
static void starfive_wdt_disable_reset(struct starfive_wdt *wdt)
{
	u32 val;

	val = readl(wdt->base + wdt->drv_data->control);
	val &= ~(STARFIVE_WDT_RESET_EN << wdt->drv_data->enrst_shift);
	writel(val, wdt->base + wdt->drv_data->control);
}

/* interrupt status whether has been raised from the counter */
static bool starfive_wdt_raise_irq_status(struct starfive_wdt *wdt)
{
	return !!readl(wdt->base + wdt->drv_data->irq_is_raise);
}

/* clear interrupt signal before initialization or reload */
static void starfive_wdt_int_clr(struct starfive_wdt *wdt)
{
	writel(STARFIVE_WDT_INTCLR, wdt->base + wdt->drv_data->int_clr);
}

static inline void starfive_wdt_set_count(struct starfive_wdt *wdt, u32 val)
{
	writel(val, wdt->base + wdt->drv_data->load);
}

static inline u32 starfive_wdt_get_count(struct starfive_wdt *wdt)
{
	return readl(wdt->base + wdt->drv_data->value);
}

/* enable watchdog */
static inline void starfive_wdt_enable(struct starfive_wdt *wdt)
{
	u32 val;

	val = readl(wdt->base + wdt->drv_data->enable);
	val |= STARFIVE_WDT_ENABLE << wdt->drv_data->en_shift;
	writel(val, wdt->base + wdt->drv_data->enable);
}

/* disable watchdog */
static inline void starfive_wdt_disable(struct starfive_wdt *wdt)
{
	u32 val;

	val = readl(wdt->base + wdt->drv_data->enable);
	val &= ~(STARFIVE_WDT_ENABLE << wdt->drv_data->en_shift);
	writel(val, wdt->base + wdt->drv_data->enable);
}

static inline void starfive_wdt_set_reload_count(struct starfive_wdt *wdt, u32 count)
{
	starfive_wdt_set_count(wdt, count);
	/* need enable controller to reload counter */
	starfive_wdt_enable(wdt);
}

static unsigned int starfive_wdt_max_timeout(struct starfive_wdt *wdt)
{
	return DIV_ROUND_UP(STARFIVE_WDT_MAXCNT, (wdt->freq / 2)) - 1;
}

static unsigned int starfive_wdt_get_timeleft(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);
	u32 count;

	starfive_wdt_unlock(wdt);
	/*
	 * Because set half count value,
	 * timeleft value should add the count value before first timeout.
	 */
	count = starfive_wdt_get_count(wdt);
	if (!starfive_wdt_raise_irq_status(wdt))
		count += wdt->count;

	starfive_wdt_lock(wdt);

	return starfive_wdt_ticks_to_sec(wdt, count);
}

static int starfive_wdt_keepalive(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);

	spin_lock(&wdt->lock);

	starfive_wdt_unlock(wdt);
	starfive_wdt_int_clr(wdt);
	starfive_wdt_set_reload_count(wdt, wdt->count);
	starfive_wdt_lock(wdt);

	spin_unlock(&wdt->lock);

	return 0;
}

static int starfive_wdt_stop(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);

	spin_lock(&wdt->lock);

	starfive_wdt_unlock(wdt);
	starfive_wdt_disable_reset(wdt);
	starfive_wdt_int_clr(wdt);
	starfive_wdt_disable(wdt);
	starfive_wdt_lock(wdt);

	spin_unlock(&wdt->lock);

	return 0;
}

static int starfive_wdt_pm_stop(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);

	starfive_wdt_stop(wdd);
	pm_runtime_put_sync(wdt->dev);

	return 0;
}

static int starfive_wdt_start(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);

	spin_lock(&wdt->lock);
	starfive_wdt_unlock(wdt);
	/* disable watchdog, to be safe */
	starfive_wdt_disable(wdt);

	starfive_wdt_enable_reset(wdt);
	starfive_wdt_int_clr(wdt);
	starfive_wdt_set_count(wdt, wdt->count);
	starfive_wdt_enable(wdt);

	starfive_wdt_lock(wdt);
	spin_unlock(&wdt->lock);

	return 0;
}

static int starfive_wdt_pm_start(struct watchdog_device *wdd)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);

	pm_runtime_get_sync(wdt->dev);

	return starfive_wdt_start(wdd);
}

static int starfive_wdt_set_timeout(struct watchdog_device *wdd,
				    unsigned int timeout)
{
	struct starfive_wdt *wdt = watchdog_get_drvdata(wdd);
	unsigned long freq = wdt->freq;

	spin_lock(&wdt->lock);

	/*
	 * This watchdog takes twice timeouts to reset.
	 * In order to reduce time to reset, should set half count value.
	 */
	wdt->count = timeout * freq / 2;
	wdd->timeout = timeout;

	starfive_wdt_unlock(wdt);
	starfive_wdt_disable(wdt);
	starfive_wdt_set_reload_count(wdt, wdt->count);
	starfive_wdt_enable(wdt);
	starfive_wdt_lock(wdt);

	spin_unlock(&wdt->lock);

	return 0;
}

#define OPTIONS (WDIOF_SETTIMEOUT | WDIOF_KEEPALIVEPING | WDIOF_MAGICCLOSE)

static const struct watchdog_info starfive_wdt_ident = {
	.options = OPTIONS,
	.identity = "StarFive Watchdog",
};

static const struct watchdog_ops starfive_wdt_ops = {
	.owner = THIS_MODULE,
	.start = starfive_wdt_pm_start,
	.stop = starfive_wdt_pm_stop,
	.ping = starfive_wdt_keepalive,
	.set_timeout = starfive_wdt_set_timeout,
	.get_timeleft = starfive_wdt_get_timeleft,
};

static const struct watchdog_device starfive_wdd = {
	.info = &starfive_wdt_ident,
	.ops = &starfive_wdt_ops,
	.timeout = STARFIVE_WDT_DEFAULT_TIME,
};

static inline const struct starfive_wdt_variant *
starfive_wdt_get_drv_data(struct platform_device *pdev)
{
	const struct starfive_wdt_variant *variant;

	variant = of_device_get_match_data(&pdev->dev);
	if (!variant) {
		/* Device matched by platform_device_id */
		variant = (struct starfive_wdt_variant *)
			   platform_get_device_id(pdev)->driver_data;
	}

	return variant;
}

static int starfive_wdt_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct starfive_wdt *wdt;
	int ret;

	wdt = devm_kzalloc(dev, sizeof(*wdt), GFP_KERNEL);
	if (!wdt)
		return -ENOMEM;

	wdt->dev = dev;
	spin_lock_init(&wdt->lock);
	wdt->wdt_device = starfive_wdd;

	wdt->drv_data = starfive_wdt_get_drv_data(pdev);

	/* get the memory region for the watchdog timer */
	wdt->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(wdt->base)) {
		ret = PTR_ERR(wdt->base);
		return ret;
	}

	platform_set_drvdata(pdev, wdt);
	pm_runtime_enable(wdt->dev);

	ret = starfive_wdt_get_clock(wdt);
	if (ret)
		return ret;

	if (pm_runtime_enabled(wdt->dev)) {
		ret = pm_runtime_get_sync(wdt->dev);
		if (ret < 0)
			return ret;
	} else {
		/* runtime PM is disabled but clocks need to be enabled */
		ret = clk_prepare_enable(wdt->apb_clk);
		if (ret) {
			dev_err(wdt->dev, "failed to enable apb_clk.\n");
			return ret;
		}
		ret = clk_prepare_enable(wdt->core_clk);
		if (ret) {
			dev_err(wdt->dev, "failed to enable core_clk.\n");
			goto err_apb_clk_disable;
		}
	}

	ret = starfive_wdt_get_clock_rate(wdt);
	if (ret)
		goto err_clk_disable;

	ret = starfive_wdt_reset_init(wdt);
	if (ret)
		goto err_clk_disable;

	wdt->wdt_device.min_timeout = 1;
	wdt->wdt_device.max_timeout = starfive_wdt_max_timeout(wdt);

	watchdog_set_drvdata(&wdt->wdt_device, wdt);

	/*
	 * see if we can actually set the requested heartbeat,
	 * and if not, try the default value.
	 */
	watchdog_init_timeout(&wdt->wdt_device, heartbeat, dev);
	if (wdt->wdt_device.timeout == 0 ||
	    wdt->wdt_device.timeout > wdt->wdt_device.max_timeout) {
		dev_warn(dev, "heartbeat value out of range, default %d used\n",
			 STARFIVE_WDT_DEFAULT_TIME);
		wdt->wdt_device.timeout = STARFIVE_WDT_DEFAULT_TIME;
	}
	starfive_wdt_set_timeout(&wdt->wdt_device, wdt->wdt_device.timeout);

	watchdog_set_nowayout(&wdt->wdt_device, nowayout);
	watchdog_stop_on_reboot(&wdt->wdt_device);
	watchdog_stop_on_unregister(&wdt->wdt_device);

	wdt->wdt_device.parent = dev;

	ret = watchdog_register_device(&wdt->wdt_device);
	if (ret)
		goto err_clk_disable;

	if (early_enable) {
		starfive_wdt_start(&wdt->wdt_device);
		set_bit(WDOG_HW_RUNNING, &wdt->wdt_device.status);
	} else {
		starfive_wdt_stop(&wdt->wdt_device);
	}

	pm_runtime_put_sync(wdt->dev);

	return 0;

err_clk_disable:
	clk_disable_unprepare(wdt->core_clk);
err_apb_clk_disable:
	clk_disable_unprepare(wdt->apb_clk);
	pm_runtime_disable(wdt->dev);

	return ret;
}

static int starfive_wdt_remove(struct platform_device *dev)
{
	struct starfive_wdt *wdt = platform_get_drvdata(dev);

	starfive_wdt_stop(&wdt->wdt_device);
	watchdog_unregister_device(&wdt->wdt_device);

	if (pm_runtime_enabled(wdt->dev)) {
		pm_runtime_disable(wdt->dev);
	} else {
		/* disable clock without PM */
		clk_disable_unprepare(wdt->core_clk);
		clk_disable_unprepare(wdt->apb_clk);
	}

	return 0;
}

static void starfive_wdt_shutdown(struct platform_device *dev)
{
	struct starfive_wdt *wdt = platform_get_drvdata(dev);

	starfive_wdt_pm_stop(&wdt->wdt_device);
}

#ifdef CONFIG_PM_SLEEP
static int starfive_wdt_suspend(struct device *dev)
{
	int ret;
	struct starfive_wdt *wdt = dev_get_drvdata(dev);

	starfive_wdt_unlock(wdt);

	/* Save watchdog state, and turn it off. */
	wdt->reload = starfive_wdt_get_count(wdt);

	/* Note that WTCNT doesn't need to be saved. */
	starfive_wdt_stop(&wdt->wdt_device);
	pm_runtime_force_suspend(dev);

	starfive_wdt_lock(wdt);

	return 0;
}

static int starfive_wdt_resume(struct device *dev)
{
	int ret;
	struct starfive_wdt *wdt = dev_get_drvdata(dev);

	starfive_wdt_unlock(wdt);

	pm_runtime_force_resume(dev);

	/* Restore watchdog state. */
	starfive_wdt_set_reload_count(wdt, wdt->reload);

	starfive_wdt_start(&wdt->wdt_device);

	starfive_wdt_lock(wdt);

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

#ifdef CONFIG_PM
static int starfive_wdt_runtime_suspend(struct device *dev)
{
	struct starfive_wdt *wdt = dev_get_drvdata(dev);

	clk_disable_unprepare(wdt->apb_clk);
	clk_disable_unprepare(wdt->core_clk);

	return 0;
}

static int starfive_wdt_runtime_resume(struct device *dev)
{
	struct starfive_wdt *wdt = dev_get_drvdata(dev);
	int ret;

	ret = clk_prepare_enable(wdt->apb_clk);
	if (ret) {
		dev_err(wdt->dev, "failed to enable apb_clk.\n");
		return ret;
	}

	ret = clk_prepare_enable(wdt->core_clk);
	if (ret)
		dev_err(wdt->dev, "failed to enable core_clk.\n");

	return ret;
}
#endif /* CONFIG_PM */

static const struct dev_pm_ops starfive_wdt_pm_ops = {
	SET_RUNTIME_PM_OPS(starfive_wdt_runtime_suspend, starfive_wdt_runtime_resume, NULL)
	SET_SYSTEM_SLEEP_PM_OPS(starfive_wdt_suspend, starfive_wdt_resume)
};

static struct platform_driver starfive_wdt_driver = {
	.probe		= starfive_wdt_probe,
	.remove		= starfive_wdt_remove,
	.shutdown	= starfive_wdt_shutdown,
	.id_table	= starfive_wdt_ids,
	.driver		= {
		.name	= "starfive-wdt",
		.pm	= &starfive_wdt_pm_ops,
		.of_match_table = of_match_ptr(starfive_wdt_match),
	},
};

module_platform_driver(starfive_wdt_driver);

MODULE_AUTHOR("Xingyu Wu <xingyu.wu@starfivetech.com>");
MODULE_AUTHOR("Samin Guo <samin.guo@starfivetech.com>");
MODULE_DESCRIPTION("StarFive Watchdog Device Driver");
MODULE_LICENSE("GPL");
