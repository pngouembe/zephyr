/** @file
 * @brief IPv6 Networking over CAN definitions.
 *
 * Definitions for IPv6 Networking over CAN support.
 */

/*
 * Copyright (c) 2019 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_INCLUDE_NET_CAN_H_
#define ZEPHYR_INCLUDE_NET_CAN_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <zephyr/types.h>
#include <net/net_ip.h>
#include <net/net_if.h>
#include <can.h>
#include <isotp.h>

/**
 * @brief IPv6 over CAN library
 * @defgroup net_can Network Core Library
 * @ingroup networking
 * @{
 */

/**
 * CAN L2 driver API. Used by 6loCAN.
 */

#define NET_CAN_DL 8
/*0x3DFF - bit 4 to 10 must not be zero. Also prevent stuffing bit*/
#define NET_CAN_MULTICAST_ADDR 0x3DFF
#define NET_CAN_DAD_ADDR       0x3DFE
#define NET_CAN_MAX_ADDR       (0x3DF0 - 1)
#define NET_CAN_MIN_ADDR       (0x00FF + 1)

#define CAN_NET_IF_ADDR_MASK       0x3FFF
#define CAN_NET_IF_ADDR_BYTE_LEN   2
#define CAN_NET_IF_ADDR_DEST_POS   15
#define CAN_NET_IF_ADDR_DEST_MASK  (CAN_NET_IF_ADDR_MASK << CAN_NET_IF_ADDR_DEST_POS)
#define CAN_NET_IF_ADDR_SRC_POS    1
#define CAN_NET_IF_ADDR_FC_POS     0
#define CAN_NET_IF_ADDR_FF_MASK    (1 << CAN_NET_IF_ADDR_FC_POS)

#define CAN_NET_FILTER_NOT_SET -1

struct net_can_api {
	/**
	 * The net_if_api must be placed in first position in this
	 * struct so that we are compatible with network interface API.
	 */
	struct net_if_api iface_api;

	/** Send a single CAN frame */
	int (*send)(struct device *dev, const struct zcan_frame *frame,
		    can_tx_callback_t cb, void *cb_arg);
	/** Attach a filter with it's callback */
	int (*attach_filter)(struct device *dev, can_rx_callback_t cb,
			     void *cb_arg, const struct zcan_filter *filter);
	/** Detach a filter */
	void (*detach_filter)(struct device *dev, int filter_id);
	/** Enable or disable the reception of First frames for net CAN */
	int (*enable)(struct device *dev, bool enable);
} __packed;

struct canbus_net_ctx {
	int dad_filter_id;
	struct k_work dad_work;
	struct net_if *iface;
	u16_t ll_addr;
};

struct net_can_lladdr {
	u16_t addr : 14;
};

struct can_net_isotp_tx_ctx {
	int filter_id;
	struct iso_tp_fc_opts opts;
	u8_t state;
	u8_t act_block_nr;
	u8_t wft;
	u8_t sn : 4;
	u8_t is_mcast : 1;
	size_t rem_len;
	struct _timeout timeout;
	struct net_pkt *pkt;
};


struct can_net_isotp_rx_ctx {
	int filter_id;
	u32_t rem_len;
	u8_t state;
	u8_t act_block_nr;
	u8_t wft;
	u8_t sn : 4;
	struct _timeout timeout;
	struct net_pkt *pkt;
};

void canbus_net_init(struct net_if *iface);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_CAN_H_ */
