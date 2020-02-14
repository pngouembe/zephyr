/*
 * Copyright (c) 2020 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 */

#ifndef ZEPHYR_DRIVERS_CAN_STM32FD_CAN_H_
#define ZEPHYR_DRIVERS_CAN_STM32FD_CAN_H_

#include <drivers/can.h>

#define DEV_DATA(dev) ((struct can_stm32_data *const)(dev)->driver_data)
#define DEV_CFG(dev) \
	((const struct can_stm32_config *const)(dev)->config->config_info)

#define BIT_SEG_LENGTH(cfg) ((cfg)->prop_ts1 + (cfg)->ts2 + 1)

#define CAN_NUMBER_OF_FILTER_BANKS (14)
#define CAN_MAX_NUMBER_OF_FILTERS (CAN_NUMBER_OF_FILTER_BANKS * 4)

struct can_stm32fd_data {
	struct k_mutex inst_mutex;
	struct k_sem tx_int_sem;
	u64_t filter_usage;
	can_rx_callback_t rx_cb[CONFIG_CAN_MAX_STD_ID_FILTER];
	can_rx_callback_t rx_cb_ext[CONFIG_CAN_MAX_EXT_ID_FILTER];
	void *cb_arg[CONFIG_CAN_MAX_STD_ID_FILTER];
	void *cb_arg_ext[CONFIG_CAN_MAX_EXT_ID_FILTER];
	can_state_change_isr_t state_change_isr;
};

struct can_stm32fd_config {
	FDCAN_GlobalTypeDef *can;   /*!< CAN Registers*/
	u32_t bus_speed;
	u8_t sjw;
	u8_t prop_ts1;
	u8_t ts2;
	u32_t bus_speed_data;
	u8_t sjw_data;
	u8_t prop_ts1_data;
	u8_t ts2_data;
	struct stm32_pclken pclken;
	void (*config_irq)(FDCAN_GlobalTypeDef *can);
};

#endif /*ZEPHYR_DRIVERS_CAN_STM32FD_CAN_H_*/
