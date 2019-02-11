/*
 * Copyright (c) 2019 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef ZEPHYR_SUBSYS_NET_CAN_ISOTP_INTERNAL_H_
#define ZEPHYR_SUBSYS_NET_CAN_ISOTP_INTERNAL_H_


#include <isotp.h>
#include <misc/slist.h>

/*
 * Abbreviations
 * BS      Block Size
 * CAN_DL  CAN LL data size
 * CF      Consecutive Frame
 * CTS     Continue to send
 * DLC     Data length code
 * FC      Flow Control
 * FF      First Frame
 * SF      Single Frame
 * FS      Flow Status
 * AE      Adders Extension
 * SN      Sequence Number
 * ST      Separation time
 * PCI     Process Control Information
 */

#ifdef ISO_TP_USE_CAN_FD
#define ISO_TP_CAN_DL CONFIG_CAN_ISO_TP_TX_DL
#else
#define ISO_TP_CAN_DL 8
#endif/*ISO_TP_USE_CAN_FD*/

/* Protocol control information*/
#define ISO_TP_PCI_SF 0x00 /* Single frame*/
#define ISO_TP_PCI_FF 0x01 /* First frame */
#define ISO_TP_PCI_CF 0x02 /* Consecutive frame */
#define ISO_TP_PCI_FC 0x03 /* Flow control frame */

#define ISO_TP_PCI_TYPE_BYTE        0
#define ISO_TP_PCI_TYPE_POS         4
#define ISO_TP_PCI_TYPE_MASK        0xF0
#define ISO_TP_PCI_TYPE_SF   (ISO_TP_PCI_SF << ISO_TP_PCI_TYPE_POS)
#define ISO_TP_PCI_TYPE_FF   (ISO_TP_PCI_FF << ISO_TP_PCI_TYPE_POS)
#define ISO_TP_PCI_TYPE_CF   (ISO_TP_PCI_CF << ISO_TP_PCI_TYPE_POS)
#define ISO_TP_PCI_TYPE_FC   (ISO_TP_PCI_FC << ISO_TP_PCI_TYPE_POS)

#define ISO_TP_PCI_SF_DL_MASK       0x0F

#define ISO_TP_PCI_FF_DL_UPPER_BYTE 0
#define ISO_TP_PCI_FF_DL_UPPER_MASK 0x0F
#define ISO_TP_PCI_FF_DL_LOWER_BYTE 1

#define ISO_TP_PCI_FS_BYTE          0
#define ISO_TP_PCI_FS_MASK          0x0F
#define ISO_TP_PCI_BS_BYTE          1
#define ISO_TP_PCI_ST_MIN_BYTE      2

#define ISO_TP_PCI_FS_CTS           0x0
#define ISO_TP_PCI_FS_WAIT          0x1
#define ISO_TP_PCI_FS_OVFLW         0x2

#define ISO_TP_PCI_SN_MASK          0x0F

#define ISO_TP_FF_DL_MIN            (ISO_TP_CAN_DL)

#define ISO_TP_STMIN_MAX            0xFA
#define ISO_TP_STMIN_MS_MAX         0x7F
#define ISO_TP_STMIN_US_BEGIN       0xF1
#define ISO_TP_STMIN_US_END         0xF9

#define ISO_TP_WFT_FIRST            0xFF

#define ISO_TP_BS K_MSEC(CONFIG_CAN_ISO_TP_BS_TIMEOUT)
#define ISO_TP_A  K_MSEC(CONFIG_CAN_ISO_TP_A_TIMEOUT)

/* Just before the sender would time out*/
#define ISO_TP_ALLOC_TIMEOUT K_MSEC(CONFIG_CAN_ISO_TP_A_TIMEOUT - 100)

#ifdef __cplusplus
extern "C" {
#endif

enum iso_tp_rx_state {
	ISO_TP_RX_STATE_WAIT_FF_SF,
	ISO_TP_RX_STATE_PROCESS_SF,
	ISO_TP_RX_STATE_PROCESS_FF,
	ISO_TP_RX_STATE_TRY_ALLOC,
	ISO_TP_RX_STATE_SEND_FC,
	ISO_TP_RX_STATE_WAIT_CF,
	ISO_TP_RX_STATE_SEND_WAIT,
	ISO_TP_RX_STATE_ERR,
	ISO_TP_RX_STATE_RECYCLE,
	ISO_TP_RX_STATE_UNBOUND
};

/*
 *+---------+       send        +---------+           +---------+
 *| RESET   |-LEN >= CAN_DL -1->| SEND FF |--FF SENT->| WAIT FC |
 *+----+----+                   +---------+           +---------+
 *     |                                                   |
 *     |     send                                    got FC|  +---STmin == 0 && data left
 *     |LEN < CAN_DL - 1                                   v  |      |
 *     |        +---------+     +---------+           +----+--+-+    |
 *     +------->| SEND SF |---->| FINISH  |<----------| SEND CF |<---+
 *              +---------+     +---------+           +-+-----+-+
 *                                                      ^     |
 *                                                      |     | STmin != 0&& data left
 *                                                      |     v
 *                                                    +-+-----+-+
 *                                                    | WAIT ST |
 *                                                    +---------+
 */
enum iso_tp_tx_state {
	ISO_TP_TX_STATE_RESET,
	ISO_TP_TX_SEND_SF,
	ISO_TP_TX_SEND_FF,
	ISO_TP_TX_WAIT_FC,
	ISO_TP_TX_SEND_CF,
	ISO_TP_TX_WAIT_ST,
	ISO_TP_TX_WAIT_FIN,
	ISO_TP_TX_ERR
};

struct iso_tp_global_ctx {
	sys_slist_t alloc_list;
	sys_slist_t ff_sf_alloc_list;
};

#ifdef __cplusplus
}
#endif

#endif /* ZEPHYR_SUBSYS_NET_CAN_ISOTP_INTERNAL_H_ */
