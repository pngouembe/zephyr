/*
 * Copyright (c) 2020 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <drivers/clock_control/stm32_clock_control.h>
#include <drivers/clock_control.h>
#include <sys/util.h>
#include <string.h>
#include <kernel.h>
#include <soc.h>
#include <stdbool.h>
#include <drivers/can.h>
#include "can_stm32fd.h"

#include <logging/log.h>
LOG_MODULE_DECLARE(can_driver, CONFIG_CAN_LOG_LEVEL);

void can_stm32fd_line_0_isr(void *arg)
{
	struct device *dev = (struct device *)arg;
}

void can_stm32fd_line_1_isr(void *arg)
{
	struct device *dev = (struct device *)arg;
}

int can_stm32fd_runtime_configure(struct device *dev, enum can_mode mode,
				u32_t bitrate)
{
	return 0;
}

static int can_stm32fd_init(struct device *dev)
{

	LOG_INF("Init of %s done", dev->config->name);
	return 0;
}

static void can_stm32fd_register_state_change_isr(struct device *dev,
						can_state_change_isr_t isr)
{

}

static enum can_state can_stm32fd_get_state(struct device *dev,
					  struct can_bus_err_cnt *err_cnt)
{
	return CAN_ERROR_ACTIVE;
}

#ifndef CONFIG_CAN_AUTO_BUS_OFF_RECOVERY
int can_stm32fd_recover(struct device *dev, s32_t timeout)
{

}
#endif /* CONFIG_CAN_AUTO_BUS_OFF_RECOVERY */


int can_stm32fd_send(struct device *dev, const struct zcan_frame *frame,
		     bool brs, bool fd_format, s32_t timeout,
		     can_tx_callback_t callback, void *callback_arg)
{
	return 0;
}

static inline int can_stm32fd_attach(struct device *dev, can_rx_callback_t cb,
				     void *cb_arg,
				     const struct zcan_filter *filter)
{
	int filter_nr;

	return filter_nr;
}

int can_stm32fd_attach_isr(struct device *dev, can_rx_callback_t isr,
			   void *cb_arg, const struct zcan_filter *filter)
{
	struct can_stm32fd_data *data = DEV_DATA(dev);
	int filter_nr;

	k_mutex_lock(&data->inst_mutex, K_FOREVER);
	filter_nr = can_stm32fd_attach(dev, isr, cb_arg, filter);
	k_mutex_unlock(&data->inst_mutex);
	return filter_nr;
}

void can_stm32fd_detach(struct device *dev, int filter_nr)
{
	struct can_stm32fd_data *data = DEV_DATA(dev);

	k_mutex_lock(&data->inst_mutex, K_FOREVER);

	k_mutex_unlock(&data->inst_mutex);
}

static const struct can_driver_api can_api_funcs = {
	.configure = can_stm32fd_runtime_configure,
	.send = can_stm32fd_send,
	.attach_isr = can_stm32fd_attach_isr,
	.detach = can_stm32fd_detach,
	.get_state = can_stm32fd_get_state,
#ifndef CONFIG_CAN_AUTO_BUS_OFF_RECOVERY
	.recover = can_stm32fd_recover,
#endif
	.register_state_change_isr = can_stm32fd_register_state_change_isr
};

#ifdef CONFIG_CAN_1

static void config_can_1_irq(FDCAN_GlobalTypeDef *can);

static const struct can_stm32fd_config can_stm32fd_cfg_1 = {
	.can = (FDCAN_GlobalTypeDef *)DT_CAN_1_BASE_ADDRESS,
	.bus_speed = DT_CAN_1_BUS_SPEED,
	.sjw = DT_CAN_1_SJW,
	.prop_ts1 = DT_CAN_1_PROP_SEG + DT_CAN_1_PHASE_SEG1,
	.ts2 = DT_CAN_1_PHASE_SEG2,
	.bus_speed_data = DT_CAN_1_BUS_SPEED_DATA,
	.sjw_data = DT_CAN_1_SJW_DATA,
	.prop_ts1_data = DT_CAN_1_PROP_SEG_DATA + DT_CAN_1_PHASE_SEG1_DATA,
	.ts2_data = DT_CAN_1_PHASE_SEG2_DATA,
	.pclken = {
		.enr = DT_CAN_1_CLOCK_BITS,
		.bus = DT_CAN_1_CLOCK_BUS,
	},
	.config_irq = config_can_1_irq
};

static struct can_stm32fd_data can_stm32fd_dev_data_1;

DEVICE_AND_API_INIT(can_stm32fd_1, DT_CAN_1_NAME, &can_stm32fd_init,
		    &can_stm32fd_dev_data_1, &can_stm32fd_cfg_1,
		    POST_KERNEL, CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		    &can_api_funcs);

static void config_can_1_irq(FDCAN_GlobalTypeDef *can)
{
	LOG_DBG("Enable CAN1 IRQ");

	IRQ_CONNECT(DT_CAN_1_IRQ_LINE_0, DT_CAN_1_IRQ_PRIORITY,
		    can_stm32fd_line_0_isr, DEVICE_GET(can_stm32fd_1), 0);
	irq_enable(DT_CAN_1_IRQ_LINE_0);

	IRQ_CONNECT(DT_CAN_1_IRQ_LINE_1, DT_CAN_1_IRQ_PRIORITY,
		    can_stm32fd_line_1_isr, DEVICE_GET(can_stm32fd_1), 0);
	irq_enable(DT_CAN_1_IRQ_LINE_1);

}

#if defined(CONFIG_NET_SOCKETS_CAN)

#include "socket_can_generic.h"

static int socket_can_init_1(struct device *dev)
{
	struct device *can_dev = DEVICE_GET(can_stm32fd_1);
	struct socket_can_context *socket_context = dev->driver_data;

	LOG_DBG("Init socket CAN device %p (%s) for dev %p (%s)",
		dev, dev->config->name, can_dev, can_dev->config->name);

	socket_context->can_dev = can_dev;
	socket_context->msgq = &socket_can_msgq;

	socket_context->rx_tid =
		k_thread_create(&socket_context->rx_thread_data,
				rx_thread_stack,
				K_THREAD_STACK_SIZEOF(rx_thread_stack),
				rx_thread, socket_context, NULL, NULL,
				RX_THREAD_PRIORITY, 0, K_NO_WAIT);

	return 0;
}

NET_DEVICE_INIT(socket_can_stm32fd_1, SOCKET_CAN_NAME_1, socket_can_init_1,
		&socket_can_context_1, NULL,
		CONFIG_KERNEL_INIT_PRIORITY_DEVICE,
		&socket_can_api,
		CANBUS_RAW_L2, NET_L2_GET_CTX_TYPE(CANBUS_RAW_L2), CAN_MTU);

#endif /* CONFIG_NET_SOCKETS_CAN */

#endif /*CONFIG_CAN_1*/
