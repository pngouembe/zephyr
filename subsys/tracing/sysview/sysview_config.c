/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <kernel.h>
#include <SEGGER_SYSVIEW.h>
#include "SEGGER_SYSVIEW_Zephyr.h"

static void cbSendSystemDesc(void)
{
	SEGGER_SYSVIEW_SendSysDesc("N=ZephyrSysView");
	SEGGER_SYSVIEW_SendSysDesc("D=" CONFIG_BOARD " "
				   CONFIG_SOC_SERIES " " CONFIG_ARCH);
	SEGGER_SYSVIEW_SendSysDesc("O=Zephyr");
}

void SEGGER_SYSVIEW_Conf(void)
{
	SEGGER_SYSVIEW_Init(sys_clock_hw_cycles_per_sec(),
			    sys_clock_hw_cycles_per_sec(),
			    &SYSVIEW_X_OS_TraceAPI, cbSendSystemDesc);

#if defined(DT_PHYS_RAM_ADDR)       /* x86 */
	SEGGER_SYSVIEW_SetRAMBase(DT_PHYS_RAM_ADDR);
#elif defined(CONFIG_SRAM_BASE_ADDRESS) /* arm, default */
	SEGGER_SYSVIEW_SetRAMBase(CONFIG_SRAM_BASE_ADDRESS);
#else
	/* Setting RAMBase is just an optimization: this value is subtracted
	 * from all pointers in order to save bandwidth.  It's not an error
	 * if a platform does not set this value.
	 */
#endif
}
