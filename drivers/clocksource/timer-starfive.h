/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Copyright (C) 2022 StarFive Technology Co., Ltd.
 */

#ifndef __STARFIVE_TIMER_H__
#define __STARFIVE_TIMER_H__

#define STARFIVE_NR_TIMERS		TIMERS_MAX
/* Bias: Timer0-0x0, Timer1-0x40, Timer2-0x80, and so on. */
#define STARFIVE_PER_TIMER_LEN		0x40
#define STARFIVE_TIMER_BASE(x)		((TIMER_##x) * STARFIVE_PER_TIMER_LEN)

#define STARFIVE_CLOCK_SOURCE_RATING	200
#define STARFIVE_VALID_BITS		32
#define STARFIVE_DELAY_US		0
#define STARFIVE_TIMEOUT_US		10000
#define STARFIVE_CLOCKEVENT_RATING	300
#define STARFIVE_MAX_TICKS		0xffffffff
#define STARFIVE_MIN_TICKS		0xf

/*
 * JH7110 timer TIMER_INT_STATUS:
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 * |     Bits     | 08~31 | 7 | 6 | 5 |  4  | 3 | 2 | 1 | 0 |
 * ----------------------------------------------------------
 * | timer(n)_int |  res  | 6 | 5 | 4 | Wdt | 3 | 2 | 1 | 0 |
 * ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
 *
 * Software can read this register to know which interrupt is occurred.
 */
#define STARFIVE_TIMER_JH7110_INT_STATUS	0x00
#define STARFIVE_TIMER_JH7110_CTL		0x04
#define STARFIVE_TIMER_JH7110_LOAD		0x08
#define STARFIVE_TIMER_JH7110_ENABLE		0x10
#define STARFIVE_TIMER_JH7110_RELOAD		0x14
#define STARFIVE_TIMER_JH7110_VALUE		0x18
#define STARFIVE_TIMER_JH7110_INT_CLR		0x20
#define STARFIVE_TIMER_JH7110_INT_MASK		0x24
#define STARFIVE_TIMER_JH7110_INT_STATUS_CLR_AVA	BIT(1)

enum STARFIVE_TIMERS {
	TIMER_0 = 0,
	TIMER_1,
	TIMER_2,
	TIMER_3,
	TIMER_4,  /*WDT*/
	TIMER_5,
	TIMER_6,
	TIMER_7,
	TIMERS_MAX
};

enum TIMERI_INTMASK {
	INTMASK_ENABLE_DIS = 0,
	INTMASK_ENABLE = 1
};

enum TIMER_MOD {
	MOD_CONTIN = 0,
	MOD_SINGLE = 1
};

enum TIMER_CTL_EN {
	TIMER_ENA_DIS	= 0,
	TIMER_ENA	= 1
};

enum {
	INT_CLR_AVAILABLE = 0,
	INT_CLR_NOT_AVAILABLE = 1
};

struct starfive_timer {
	u32 ctrl;
	u32 load;
	u32 enable;
	u32 reload;
	u32 value;
	u32 intclr;
	u32 intmask;
	u32 wdt_lock;   /* 0x3c+i*0x40 watchdog use ONLY */
	u32 timer_base[STARFIVE_NR_TIMERS];
};

struct starfive_clkevt {
	struct clock_event_device evt;
	struct clk *clk;
	struct reset_control *rst;
	char name[20];
	int irq;
	u32 periodic;
	u32 rate;
	u32 reload_val;
	void __iomem *base;
	void __iomem *ctrl;
	void __iomem *load;
	void __iomem *enable;
	void __iomem *reload;
	void __iomem *value;
	void __iomem *intclr;
	void __iomem *intmask;
};
#endif /* __STARFIVE_TIMER_H__ */
