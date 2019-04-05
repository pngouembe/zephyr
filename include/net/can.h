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

/**
 * @brief IPv6 over CAN library
 * @defgroup net_can Network Core Library
 * @ingroup networking
 * @{
 */

/**
 * CAN L2 driver API. Used by 6loCAN.
 */

/** @cond INTERNAL_HIDDEN */

#define NET_CAN_DL 8
/*0x3DFF - bit 4 to 10 must not be zero. Also prevent stuffing bit*/
#define NET_CAN_MULTICAST_ADDR 0x3DFF
#define NET_CAN_DAD_ADDR       0x3DFE
#define NET_CAN_MAX_ADDR       (0x3DF0 - 1)
#define NET_CAN_MIN_ADDR       (0x00FF + 1)

#define CAN_NET_IF_ADDR_MASK       0x3FFF
#define CAN_NET_IF_ADDR_BYTE_LEN   2
#define CAN_NET_IF_ADDR_DEST_POS   14
#define CAN_NET_IF_ADDR_DEST_MASK  (CAN_NET_IF_ADDR_MASK << CAN_NET_IF_ADDR_DEST_POS)
#define CAN_NET_IF_ADDR_SRC_POS    0

#define CAN_NET_FILTER_NOT_SET -1

/** @endcond */


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
	/** Enable or disable the reception of frames for net CAN */
	int (*enable)(struct device *dev, bool enable);
};

/** @cond INTERNAL_HIDDEN */

/**
 * Context for canbus net device.
 */
struct canbus_net_ctx {
	int dad_filter_id;
	struct k_work dad_work;
	struct net_if *iface;
	u16_t ll_addr;
};

/**
 * Canbus link layer addresses have a length of 14 bit for source and destination.
 * Both together are 28 bit to fit a CAN extended identifier with 29 bit length.
 */
struct net_can_lladdr {
	u16_t addr : 14;
};

/*
 * STmin is split in two ranges:
 *   0-127: 0ms-127ms
 * 128-240: Reserved
 * 241-249: 100us-900us (multiples of 100us)
 * 250-   : Reserved
 */
struct can_net_fc_opts {
	u8_t bs;     /** Block size. Number of CF PDUs before next CF is sent */
	u8_t stmin;  /** Minimum separation time. Min time between frames */
};

/**
 * Context for a transmission of messages that didn't fit in a single frame.
 * This messages Start with a FF (First Frame) that is in case of unicast
 * acknowledged by a FC (Frame Control). After that N CF (Consecutive frames)
 * carry the rest of the message.
 */
struct can_net_isotp_tx_ctx {
	/** Frame Control options received from FC frame */
	struct can_net_fc_opts opts;
	/** State of the transmission */
	u8_t state;
	/** Actual block number that is transmitted. Counts from BS to 0 */
	u8_t act_block_nr;
	/** Number of WAIT frames received*/
	u8_t wft;
	/** Sequence number that is added to CF*/
	u8_t sn : 4;
	/** Transmission is multicast */
	u8_t is_mcast : 1;
	/** Remaining data to transbit in bytes */
	size_t rem_len;
	/** Timeout for TX Timeout and separation time*/
	struct _timeout timeout;
	/** Pkt containing the data to transmit */
	struct net_pkt *pkt;
};


struct can_net_isotp_rx_ctx {
	/** Remaining data to receive. Goes from message length to zero */
	u32_t rem_len;
	/** State of the reception */
	u8_t state;
	/** Number of frames received in this block. Counts from BS to 0*/
	u8_t act_block_nr;
	/** Number of WAIT frames transmitted */
	u8_t wft;
	/** Expected sequence number in CF */
	u8_t sn : 4;
	/** Timeout for RX timeout*/
	struct _timeout timeout;
	/** Pkt that is large enough to hold the entire message */
	struct net_pkt *pkt;
};

/**
 * Initialization of the canbus L2.
 *
 * This function starts the TX workqueue and does some initialization.
 */
void canbus_net_init(struct net_if *iface);

/** @endcond */

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_INCLUDE_NET_CAN_H_ */
