/*
 * Copyright (c) 2019 Alexander Wachter.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <logging/log.h>
LOG_MODULE_REGISTER(net_l2_canbus, CONFIG_NET_L2_CANBUS_LOG_LEVEL);

#include <net/net_core.h>
#include <net/net_l2.h>
#include <net/net_if.h>
#include <net/net_pkt.h>
#include <net/can.h>
#include "canbus_internal.h"
#include <6lo.h>
#include <timeout_q.h>
#include <string.h>
#include <misc/byteorder.h>

#define NET_CAN_WFTMAX 2
#define NET_CAN_ALLOC_TIMEOUT K_MSEC(100)

/*Minimal separation time betwee frames*/
#define NET_CAN_STMIN 0

#define NET_CAN_DAD_SEND_RETRY 5
#define NET_CAN_DAD_TIMEOUT K_MSEC(100)

static struct can_net_isotp_tx_ctx tx_ctx[CONFIG_NET_PKT_TX_COUNT];
static struct can_net_isotp_rx_ctx rx_ctx[CONFIG_NET_PKT_RX_COUNT];
static struct k_mutex tx_ctx_mtx;
static struct k_mutex rx_ctx_mtx;
static struct k_work_q net_can_workq;
K_THREAD_STACK_DEFINE(net_can_stack, 768);
static struct k_work_q net_can_workq;
static struct k_sem tx_sem;

static void free_tx_ctx(struct can_net_isotp_tx_ctx *ctx)
{
	ctx->state = NET_CAN_TX_STATE_UNUSED;
}

static void free_rx_ctx(struct can_net_isotp_rx_ctx *ctx)
{
	ctx->state = NET_CAN_RX_STATE_UNUSED;
}

static void tx_finish(struct net_pkt *pkt)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct can_net_isotp_tx_ctx *ctx = pkt->can_tx_ctx;

	if (ctx->state != NET_CAN_TX_STATE_RESET) {
		z_abort_timeout(&ctx->timeout);
	}

	if (ctx->filter_id != CAN_NET_FILTER_NOT_SET) {
		api->detach_filter(net_can_dev, ctx->filter_id);
	}

	free_tx_ctx(ctx);
	net_pkt_unref(pkt);
	k_sem_give(&tx_sem);
}

static void rx_finish(struct net_pkt *pkt)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct can_net_isotp_rx_ctx *ctx = pkt->can_rx_ctx;

	if (ctx->filter_id != CAN_NET_FILTER_NOT_SET) {
		api->detach_filter(net_can_dev, ctx->filter_id);
	}

	free_rx_ctx(ctx);
}

static void tx_report_err(struct net_pkt *pkt)
{
	tx_finish(pkt);
}

static void rx_report_err(struct net_pkt *pkt)
{
	rx_finish(pkt);
	net_pkt_unref(pkt);
}

static void rx_err_work_handler(struct k_work *item)
{
	struct net_pkt *pkt = CONTAINER_OF(item, struct net_pkt, work);

	rx_report_err(pkt);
}

static void rx_report_err_from_isr(struct net_pkt *pkt)
{
	k_work_init(&pkt->work, rx_err_work_handler);
	k_work_submit_to_queue(&net_can_workq, &pkt->work);
}

static void tx_timeout(struct _timeout *t)
{
	struct can_net_isotp_tx_ctx *ctx =
		CONTAINER_OF(t, struct can_net_isotp_tx_ctx, timeout);
	NET_ERR("TX Timeout. CTX: %p", ctx);
	ctx->state = NET_CAN_TX_STATE_ERR;
	k_work_submit_to_queue(&net_can_workq, &ctx->pkt->work);
}


static void rx_timeout(struct _timeout *t)
{
	struct can_net_isotp_rx_ctx *ctx =
		CONTAINER_OF(t, struct can_net_isotp_rx_ctx, timeout);
	NET_ERR("RX Timeout. CTX: %p", ctx);
	ctx->state = NET_CAN_RX_STATE_TIMEOUT;
	rx_report_err_from_isr(ctx->pkt);
}

static void st_min_timeout(struct _timeout *t)
{
	struct can_net_isotp_tx_ctx *ctx =
		CONTAINER_OF(t, struct can_net_isotp_tx_ctx, timeout);
	k_work_submit_to_queue(&net_can_workq, &ctx->pkt->work);
}

static s32_t stmin_to_ticks(u8_t stmin)
{
	s32_t time_ms;
	/* According to ISO 15765-2 stmin should be 127ms if value is corrupt */
	if (stmin > NET_CAN_STMIN_MAX ||
	    (stmin > NET_CAN_STMIN_MS_MAX && stmin < NET_CAN_STMIN_US_BEGIN)) {
		time_ms = K_MSEC(NET_CAN_STMIN_MS_MAX);
	} else if (stmin >= NET_CAN_STMIN_US_BEGIN) {
		/* This should be 100us-900us but zephyr can't handle that*/
		time_ms = K_MSEC(1);
	} else {
		time_ms = stmin;
	}

	return z_ms_to_ticks(time_ms);
}

static struct can_net_isotp_rx_ctx *alloc_rx_ctx(struct net_pkt *pkt)
{
	int i;
	struct can_net_isotp_rx_ctx *ret = NULL;

	k_mutex_lock(&rx_ctx_mtx, K_FOREVER);
	for (i = 0; i < ARRAY_SIZE(rx_ctx); i++) {
		if (rx_ctx[i].state == NET_CAN_RX_STATE_UNUSED) {
			rx_ctx[i].state = NET_CAN_RX_STATE_RESET;
			rx_ctx[i].filter_id = CAN_NET_FILTER_NOT_SET;
			z_init_timeout(&rx_ctx[i].timeout, rx_timeout);
			rx_ctx[i].pkt = pkt;
			pkt->can_rx_ctx = &rx_ctx[i];
			ret = &rx_ctx[i];
			break;
		}
	}

	k_mutex_unlock(&rx_ctx_mtx);
	return ret;
}

static struct can_net_isotp_tx_ctx *alloc_tx_ctx(struct net_pkt *pkt)
{
	int i;
	struct can_net_isotp_tx_ctx *ret = NULL;

	k_mutex_lock(&tx_ctx_mtx, K_FOREVER);
	for (i = 0; i < ARRAY_SIZE(tx_ctx); i++) {
		if (tx_ctx[i].state == NET_CAN_TX_STATE_UNUSED) {
			tx_ctx[i].state = NET_CAN_TX_STATE_RESET;
			tx_ctx[i].filter_id = CAN_NET_FILTER_NOT_SET;
			z_init_timeout(&tx_ctx[i].timeout, tx_timeout);
			tx_ctx[i].pkt = pkt;
			pkt->can_tx_ctx = &tx_ctx[i];
			ret = &tx_ctx[i];
			break;
		}
	}

	k_mutex_unlock(&tx_ctx_mtx);
	return ret;
}

int get_ff_length(struct zcan_frame *frame, u32_t *length)
{
	size_t len;
	int index = 2;

	len = ((frame->data[0] & NET_CAN_PCI_FF_DL_UPPER_MASK) << 8) +
		frame->data[1];

	if (!len) {
		len = sys_be32_to_cpu(UNALIGNED_GET((u32_t *)&frame->data[2]));
		index += sizeof(u32_t);
	}

	*length = len;
	return index;
}


static inline size_t get_sf_length(struct zcan_frame *frame)
{
	return frame->data[0] & NET_CAN_PCI_SF_DL_MASK;
}

static inline bool is_ff(struct zcan_frame *frame)
{
	u8_t pci_type = frame->data[0] & NET_CAN_PCI_TYPE_MASK;

	return (pci_type == NET_CAN_PCI_TYPE_FF);
}

static inline bool is_sf(struct zcan_frame *frame)
{
	u8_t pci_type = frame->data[0] & NET_CAN_PCI_TYPE_MASK;

	return (pci_type == NET_CAN_PCI_TYPE_SF);
}

static inline u8_t get_frame_datalength(struct zcan_frame *frame)
{
	/* TODO: Needs update when CAN FD support is added*/
	return frame->dlc;
}

static inline void set_frame_datalength(struct zcan_frame *frame, u8_t length)
{
	/* TODO: Needs update when CAN FD support is added*/
	NET_ASSERT(length <= NET_CAN_DL);
	frame->dlc = length;
}

static enum net_verdict finish_pkt(struct net_pkt *pkt)
{
	net_pkt_cursor_init(pkt);

	if (!net_6lo_uncompress(pkt)) {
		NET_ERR("6lo uncompression failed");
		return NET_DROP;
	}

	return NET_CONTINUE;
}

static inline void get_can_lladdr_src(struct zcan_frame *frame,
				      struct net_can_lladdr *addr)
{
	addr->addr = (frame->ext_id >> CAN_NET_IF_ADDR_SRC_POS) &
		     CAN_NET_IF_ADDR_MASK;
}

static inline void get_can_lladdr_dest(struct zcan_frame *frame,
				       struct net_can_lladdr *addr)
{
	addr->addr = (frame->ext_id >> CAN_NET_IF_ADDR_DEST_POS) &
		     CAN_NET_IF_ADDR_MASK;
}

static inline void set_lladdr(struct net_pkt *pkt,
			      struct net_can_lladdr *src,
			      struct net_can_lladdr *dest)
{
	struct net_buf *buf = pkt->buffer;

	NET_ASSERT(buf->size >= sizeof(struct net_can_lladdr) * 2);

	net_pkt_lladdr_src(pkt)->addr = buf->data;
	net_pkt_lladdr_src(pkt)->len = sizeof(struct net_can_lladdr);
	net_pkt_lladdr_src(pkt)->type = NET_LINK_CANBUS;
	net_buf_add_be16(buf, src->addr);
	net_buf_pull(buf, sizeof(u16_t));

	net_pkt_lladdr_dst(pkt)->addr = buf->data;
	net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_can_lladdr);
	net_pkt_lladdr_dst(pkt)->type = NET_LINK_CANBUS;
	net_buf_add_be16(buf, dest->addr);
	net_buf_pull(buf, sizeof(u16_t));

	net_pkt_set_family(pkt, AF_INET6);
	net_pkt_cursor_init(pkt);
}

static inline u32_t addr_to_id(u16_t dest, u16_t src, bool is_ff)
{
	return (dest << CAN_NET_IF_ADDR_DEST_POS) |
	       (src  << CAN_NET_IF_ADDR_SRC_POS) |
	       (is_ff ? CAN_NET_IF_ADDR_FF_MASK : 0);
}

static void set_frame_addr(struct zcan_frame *frame,
			   const struct net_can_lladdr *dest,
			   const struct net_can_lladdr *src,
			   bool is_ff)
{
	frame->id_type = CAN_EXTENDED_IDENTIFIER;
	frame->rtr = CAN_DATAFRAME;

	frame->ext_id = addr_to_id(dest->addr, src->addr, is_ff);
}


static void set_frame_addr_pkt(struct zcan_frame *frame, struct net_pkt *pkt,
			   bool is_ff, bool mcast)
{
	u8_t *src_link_addr = net_if_get_link_addr(pkt->iface)->addr;
	u8_t *dest_link_addr = net_pkt_lladdr_dst(pkt)->addr;
	struct net_can_lladdr src_addr, dest_addr;

	dest_addr.addr = mcast ? NET_CAN_MULTICAST_ADDR :
			sys_be16_to_cpu(UNALIGNED_GET((u16_t *)dest_link_addr));
	src_addr.addr = sys_be16_to_cpu(UNALIGNED_GET((u16_t *)src_link_addr));

	set_frame_addr(frame, &dest_addr, &src_addr, is_ff);
}

static void canbus_net_cf_callback(struct zcan_frame *frame, void *arg)
{
	struct can_net_isotp_rx_ctx *ctx = (struct can_net_isotp_rx_ctx *)arg;
	struct net_pkt *pkt = ctx->pkt;
	u8_t data_len = get_frame_datalength(frame) - 1;
	int ret;

	z_abort_timeout(&ctx->timeout);

	if (ctx->state != NET_CAN_RX_STATE_CF) {
		NET_ERR("Got CF in state %d. CTX: %p", ctx->state, ctx);
		rx_report_err_from_isr(pkt);
		return;
	}

	if ((frame->data[0] & NET_CAN_PCI_TYPE_MASK) != NET_CAN_PCI_TYPE_CF) {
		NET_ERR("Waiting for CF but got something else (%d)",
			frame->data[0] >> NET_CAN_PCI_TYPE_POS);
		rx_report_err_from_isr(pkt);
		return;
	}

	if ((frame->data[0] & NET_CAN_PCI_SN_MASK) != ctx->sn) {
		NET_ERR("Sequence number missmatch. Expect %u, got %u",
			ctx->sn, frame->data[0] & NET_CAN_PCI_SN_MASK);
		rx_report_err_from_isr(pkt);
		return;
	}

	ctx->sn++;

	if (data_len > ctx->rem_len) {
		NET_DBG("Remove padding of %d bytes", data_len - ctx->rem_len);
		data_len = ctx->rem_len;
	}

	NET_DBG("Appending CF data to pkt (%d bytes)", data_len);
	ret = net_pkt_write(pkt, &frame->data[1], data_len);
	if (ret < 0) {
		NET_ERR("Failed to write data to pkt [%d]", ret);
		rx_report_err_from_isr(pkt);
	}

	ctx->rem_len -= data_len;

	NET_DBG("%u bytes remaining", ctx->rem_len);

	if (ctx->rem_len == 0) {
		ctx->state = NET_CAN_RX_STATE_FIN;
		ret = net_recv_data(pkt->iface, pkt);
		if (ret < 0) {
			NET_ERR("Packet dropped by NET stack");
			net_pkt_unref(pkt);
		}
	} else {
		z_add_timeout(&ctx->timeout, rx_timeout,
			      z_ms_to_ticks(NET_CAN_BS));
	}
}

static void fc_send_cb(u32_t err_flags, void *arg)
{
	if (err_flags) {
		NET_ERR("Sending FC frame failed: %d", err_flags);
	}
}

static int send_fc(struct device *net_can_dev, struct net_can_lladdr *src,
		   struct net_can_lladdr *dest, u8_t fs)
{
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame = {
		.id_type  = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
	};
	int ret;

	NET_ASSERT(!(fs & NET_CAN_PCI_TYPE_MASK));

	set_frame_addr(&frame, dest, src, false);

	frame.data[0] = NET_CAN_PCI_TYPE_FC | fs;
	/* Block size of 0. This means that all data is sent without waiting for
	 * additional FC frames
	 */
	frame.data[1] = 0;
	/*STmin*/
	frame.data[2] = NET_CAN_STMIN;
	set_frame_datalength(&frame, 3);

	ret = api->send(net_can_dev, &frame, fc_send_cb, NULL);
	return ret;
}

static inline int attach_cf_filter(struct device *net_can_dev,
				   struct can_net_isotp_rx_ctx *rx_ctx,
				   struct net_can_lladdr *dest,
				   struct net_can_lladdr *src)
{
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
		.rtr_mask = 1,
		.ext_id_mask = CAN_EXT_ID_MASK
	};
	const struct net_can_api *api = net_can_dev->driver_api;
	int filter_id;

	filter.ext_id = addr_to_id(dest->addr, src->addr, false);
	filter_id = api->attach_filter(net_can_dev, canbus_net_cf_callback,
				       rx_ctx, &filter);
	if (filter_id == CAN_NO_FREE_FILTER) {
		NET_ERR("Can't attach CF filter.");
	} else {
		NET_DBG("Attached CF filter %d.", filter_id);
	}

	return filter_id;
}

static enum net_verdict process_ff(struct net_pkt *pkt,
				   struct zcan_frame *frame)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	struct can_net_isotp_rx_ctx *rx_ctx = NULL;
	struct net_pkt *new_pkt = NULL;
	int filter_id;
	int index, ret;
	struct net_can_lladdr src, dest;
	u32_t msg_len;
	u8_t data_len;
	bool mcast;

	get_can_lladdr_src(frame, &src);
	get_can_lladdr_dest(frame, &dest);
	mcast = dest.addr == NET_CAN_MULTICAST_ADDR;

	index = get_ff_length(frame, &msg_len);
	new_pkt = net_pkt_rx_alloc_with_buffer(pkt->iface,
					       msg_len + 2 * sizeof(struct net_can_lladdr),
					       AF_INET6, 0,
					       NET_CAN_ALLOC_TIMEOUT);
	if (!new_pkt) {
		NET_ERR("Failed to obtain net_pkt with size of %d",
			msg_len + 2 * sizeof(struct net_can_lladdr));

		if (!mcast) {
			send_fc(net_can_dev, &dest, &src, NET_CAN_PCI_FS_OVFLW);
		}

		goto err;
	}

	rx_ctx = alloc_rx_ctx(new_pkt);
	if (!rx_ctx) {
		NET_ERR("No rx context left");
		net_pkt_unref(new_pkt);

		if (!mcast) {
			send_fc(net_can_dev, &dest, &src, NET_CAN_PCI_FS_OVFLW);
		}

		goto err;
	}

	rx_ctx->sn = 1;
	data_len = get_frame_datalength(frame) - index;
	set_lladdr(new_pkt, &src, &dest);
	ret = net_pkt_write(new_pkt, &frame->data[index], data_len);
	if (ret) {
		NET_ERR("Failed to write to pkt [%d]", ret);
		goto err;
	}

	rx_ctx->rem_len = msg_len - data_len;

	filter_id = attach_cf_filter(net_can_dev, rx_ctx, &dest, &src);
	if (filter_id < 0) {
		NET_ERR("Failed to attach CF filter [%d]", filter_id);

		if (!mcast) {
			send_fc(net_can_dev, &dest, &src, NET_CAN_PCI_FS_OVFLW);
		}

		goto err;
	}

	rx_ctx->filter_id = filter_id;

	if (!mcast) {
		/* switch src and dest because we are answering */
		ret = send_fc(net_can_dev, &dest, &src, NET_CAN_PCI_FS_CTS);
		if (ret) {
			NET_ERR("Failed to send FC CTS.");
			rx_report_err(new_pkt);
			return NET_DROP;
		}
	}
	/* At this point we expect to get Consecutive frames directly */
	z_add_timeout(&rx_ctx->timeout, rx_timeout, z_ms_to_ticks(NET_CAN_BS));

	rx_ctx->state = NET_CAN_RX_STATE_CF;
	if (mcast) {
		NET_DBG("Processed FF (multicast). Msg length: %u CTX: %p",
			msg_len, rx_ctx);
	} else {
		NET_DBG("Processed FF (unicast). Msg length: %u CTX: %p",
			msg_len, rx_ctx);
	}

	return NET_OK;

err:
	if (new_pkt) {
		net_pkt_unref(new_pkt);
	}

	if (rx_ctx) {
		free_rx_ctx(rx_ctx);
	}
	return NET_DROP;
}

static enum net_verdict process_sf(struct net_pkt *pkt,
				   struct zcan_frame *frame)
{
	size_t rem_frame_hdr_len = frame->data - (u8_t *)net_pkt_data(pkt);
	size_t data_len = get_sf_length(frame);
	size_t pkt_len;
	struct net_can_lladdr src, dest;

	get_can_lladdr_src(frame, &src);
	get_can_lladdr_dest(frame, &dest);
	set_lladdr(pkt, &src, &dest);
	NET_ASSERT(rem_frame_hdr_len >= 0);
	net_pkt_pull(pkt, rem_frame_hdr_len);
	pkt_len = net_pkt_get_len(pkt);

	if (data_len > pkt_len) {
		NET_ERR("SF datalen > pkt size");
		return NET_DROP;
	}
	if (pkt_len != data_len) {
		NET_DBG("Remove padding (%d byte)", pkt_len - data_len);
		net_pkt_update_length(pkt, data_len);
	}

	return NET_CONTINUE;
}

static enum net_verdict process_ff_fs(struct net_pkt *pkt)
{
	struct zcan_frame frame;

	net_pkt_cursor_init(pkt);
	net_pkt_read(pkt, &frame, sizeof(struct zcan_frame));

	NET_ASSERT(frame.id_type == CAN_EXTENDED_IDENTIFIER);

	if (is_sf(&frame)) {
		NET_DBG("PKT is SF");
		return process_sf(pkt, &frame);
	} else if (is_ff(&frame)) {
		NET_DBG("PKT is FF");
		return process_ff(pkt, &frame);
	}

	NET_ERR("Unexpected PCI type");
	return NET_DROP;
}

static enum net_verdict canbus_recv(struct net_if *iface,
					   struct net_pkt *pkt)
{
	enum net_verdict ret = NET_DROP;

	if (pkt->can_rx_ctx) {
		NET_DBG("Push reassembled packet trough stack again");
		if (pkt->can_rx_ctx->state == NET_CAN_RX_STATE_FIN) {
			rx_finish(pkt);
			finish_pkt(pkt);
			ret = NET_CONTINUE;
		} else {
			NET_ERR("Expected pkt in FIN state");
		}
	} else{
		NET_DBG("PKT from net if %p", pkt);
		ret = process_ff_fs(pkt);
	}

	return ret;
}

static void tx_frame_isr(u32_t err_flags, void *arg)
{
	struct net_pkt *pkt = (struct net_pkt *)arg;

	k_work_submit_to_queue(&net_can_workq, &pkt->work);
}

static inline int send_cf(struct net_pkt *pkt)
{
	struct can_net_isotp_tx_ctx *ctx = pkt->can_tx_ctx;
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret;
	int len;

	set_frame_addr_pkt(&frame, pkt, false, ctx->is_mcast);

	/*sn wraps around at 0xF automatically because it has a 4 bit size*/
	frame.data[0] = NET_CAN_PCI_TYPE_CF | ctx->sn++;

	len = MIN(ctx->rem_len, NET_CAN_DL - 1);
	ctx->rem_len -= len;

	set_frame_datalength(&frame, len + 1);

	net_pkt_read(pkt, &frame.data[1], len);
	ret = api->send(net_can_dev, &frame, tx_frame_isr, pkt);

	return ret ? ret : ctx->rem_len;
}

static void tx_work(struct net_pkt *pkt)
{
	int ret;
	struct can_net_isotp_tx_ctx *ctx = pkt->can_tx_ctx;

	NET_ASSERT(ctx);

	switch (ctx->state) {
	case NET_CAN_TX_STATE_SEND_CF:
		ret = send_cf(ctx->pkt);
		NET_DBG("CF sent. %d bytes left. CTX: %p", ret, ctx);
		if (!ret) {
			ctx->state = NET_CAN_TX_STATE_FIN;
			break;
		}

		if (ret < 0) {
			NET_ERR("Failed to send CF. CTX: %p", ctx);
			tx_report_err(pkt);
			break;
		}

		if (ctx->opts.bs && !--ctx->act_block_nr) {
			NET_DBG("BS reached. Wait for FC again. CTX: %p", ctx);
			ctx->state = NET_CAN_TX_STATE_WAIT_FC;
			z_add_timeout(&ctx->timeout, tx_timeout,
			      z_ms_to_ticks(NET_CAN_BS));
		} else if (ctx->opts.stmin) {
			ctx->state = NET_CAN_TX_STATE_WAIT_ST;
		}

		break;

	case NET_CAN_TX_STATE_WAIT_ST:
		NET_DBG("SM wait ST. CTX: %p", ctx);
		z_add_timeout(&ctx->timeout, st_min_timeout,
			      z_ms_to_ticks(stmin_to_ticks(ctx->opts.stmin)));
		ctx->state = NET_CAN_TX_STATE_SEND_CF;
		break;

	case NET_CAN_TX_STATE_ERR:
		NET_DBG("SM handle error. CTX: %p", ctx);
		tx_report_err(pkt);
		break;

	case NET_CAN_TX_STATE_FIN:
		NET_DBG("SM finish. CTX: %p", ctx);
		tx_finish(ctx->pkt);
		break;

	default:
		break;
	}
}

static void tx_work_handler(struct k_work *item)
{
	struct net_pkt *pkt = CONTAINER_OF(item, struct net_pkt, work);

	tx_work(pkt);
}

static void process_fc(struct can_net_isotp_tx_ctx *ctx,
		       struct zcan_frame *frame)
{
	if ((frame->data[0] & NET_CAN_PCI_TYPE_MASK) != NET_CAN_PCI_TYPE_FC) {
		NET_ERR("Got unexpected PDU. ID 0x%08x while expecting FC."
			"CTX: %p", frame->ext_id, ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
		return;
	}

	switch (frame->data[0] & NET_CAN_PCI_FS_MASK) {
	case NET_CAN_PCI_FS_CTS:
		ctx->state = NET_CAN_TX_STATE_SEND_CF;
		ctx->wft = 0;
		ctx->opts.bs = frame->data[1];
		ctx->opts.stmin = frame->data[2];
		ctx->act_block_nr = ctx->opts.bs;
		z_abort_timeout(&ctx->timeout);
		NET_DBG("Got CTS. BS: %d, STmin: %d. CTX: %p",
			ctx->opts.bs, ctx->opts.stmin, ctx);
		break;
	case NET_CAN_PCI_FS_WAIT:
		NET_DBG("Got WAIT frame. CTX: %p", ctx);
		z_abort_timeout(&ctx->timeout);
		z_add_timeout(&ctx->timeout, tx_timeout,
			      z_ms_to_ticks(NET_CAN_BS));
		if (ctx->wft >= NET_CAN_WFTMAX) {
			NET_INFO("Got to many wait frames. CTX: %p", ctx);
			ctx->state = NET_CAN_TX_STATE_ERR;
		}

		ctx->wft++;
		break;
	case NET_CAN_PCI_FS_OVFLW:
		NET_ERR("Got overflow FC frame. CTX: %p", ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
		break;
	default:
		NET_ERR("Invalid Frame Status. CTX: %p", ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
	}
}

static void canbus_net_fc_callback(struct zcan_frame *frame, void *arg)
{
	struct can_net_isotp_tx_ctx *ctx = (struct can_net_isotp_tx_ctx *)arg;

	NET_ASSERT(ctx);

	if (ctx->state == NET_CAN_TX_STATE_WAIT_FC) {
		process_fc(ctx, frame);
	} else {
		struct net_can_lladdr src, dest;

		get_can_lladdr_src(frame, &src);
		get_can_lladdr_dest(frame, &dest);
		NET_ERR("Got unexpected PDU."
			" ID: 0x%08x(from: 0x%04x to: 0x%04x). CTX: %p",
			frame->ext_id, src.addr, dest.addr, ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
	}

	k_work_submit_to_queue(&net_can_workq, &ctx->pkt->work);
}

static inline int send_ff(struct net_pkt *pkt, size_t len, bool mcast)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret, index = 0;

	set_frame_addr_pkt(&frame, pkt, true, mcast);
	set_frame_datalength(&frame, NET_CAN_DL);

	if (mcast) {
		NET_DBG("Sending FF (multicast). ID: 0x%08x. PKT len: %zu."
			" CTX: %p",
			frame.ext_id, len, tx_ctx);
	} else {
		NET_DBG("Sending FF (unicast). ID: 0x%08x. PKT len: %zu."
			" CTX: %p",
			frame.ext_id, len, tx_ctx);
	}

	if (len > 0x0FFF) {
		frame.data[index++] = NET_CAN_PCI_TYPE_FF;
		frame.data[index++] = 0;
		frame.data[index++] = (len >> 3*8) & 0xFF;
		frame.data[index++] = (len >> 2*8) & 0xFF;
		frame.data[index++] = (len >>   8) & 0xFF;
		frame.data[index++] = len & 0xFF;
	} else {
		frame.data[index++] = NET_CAN_PCI_TYPE_FF | (len >> 8);
		frame.data[index++] = len & 0xFF;
	}

	/* According to ISO FF has sn 0 and is incremented to one
	 * alltough it's not part of the FF frame
	 */
	pkt->can_tx_ctx->sn = 1;

	net_pkt_read(pkt, &frame.data[index], NET_CAN_DL - index);
	pkt->can_tx_ctx->rem_len -= NET_CAN_DL - index;

	ret = api->send(net_can_dev, &frame, NULL, NULL);
	if (ret != CAN_TX_OK) {
		NET_ERR("Sending FF failed [%d]. CTX: %p", ret, pkt->can_tx_ctx);
	}

	return ret;
}

static inline int send_single_frame(struct net_pkt *pkt, size_t len, bool mcast)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret;

	set_frame_addr_pkt(&frame, pkt, true, mcast);

	frame.data[0] = NET_CAN_PCI_TYPE_SF | len;

	NET_ASSERT(len <= NET_CAN_DL - 1);
	net_pkt_read(pkt, &frame.data[1], len);

	set_frame_datalength(&frame, len + 1);

	ret = api->send(net_can_dev, &frame, NULL, NULL);
	if (ret != CAN_TX_OK) {
		NET_ERR("Sending SF failed [%d]", ret);
		return -EIO;
	}

	return 0;
}

static inline int attach_fc_filter(struct device *net_can_dev,
			    struct can_net_isotp_tx_ctx *tx_ctx,
			    struct net_pkt *pkt)
{
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
		.rtr_mask = 1,
		.ext_id_mask = CAN_EXT_ID_MASK
	};
	const struct net_can_api *api = net_can_dev->driver_api;
	const u8_t *dest = net_pkt_lladdr_dst(pkt)->addr;
	const u8_t *src = net_if_get_link_addr(pkt->iface)->addr;
	int filter_id;

	/* Frame Control frames are sent from destination (receiver) to our addr (src) */
	filter.ext_id = addr_to_id(sys_be16_to_cpu(UNALIGNED_GET((u16_t *)src)),
				   sys_be16_to_cpu(UNALIGNED_GET((u16_t *)dest)),
				   false);

	filter_id = api->attach_filter(net_can_dev, canbus_net_fc_callback,
				       tx_ctx, &filter);
	if (filter_id == CAN_NO_FREE_FILTER) {
		NET_ERR("Can't attach FC filter. CTX: %p", tx_ctx);
	} else {
		NET_DBG("Attached FC filter %d. CTX: %p", filter_id, tx_ctx);
	}

	return filter_id;
}

static void start_sending_cf(struct _timeout *t)
{
	struct can_net_isotp_tx_ctx *ctx =
		CONTAINER_OF(t, struct can_net_isotp_tx_ctx, timeout);
	k_work_submit_to_queue(&net_can_workq, &ctx->pkt->work);
}

static inline int send_multiple_frames(struct net_pkt *pkt, size_t len,
				       bool mcast)
{
	struct can_net_isotp_tx_ctx *tx_ctx = NULL;
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	int ret;

	tx_ctx = alloc_tx_ctx(pkt);
	if (!tx_ctx) {
		NET_ERR("No tx context left");
		k_sem_give(&tx_sem);
		return -EAGAIN;
	}

	tx_ctx->is_mcast = mcast;
	tx_ctx->rem_len = net_pkt_get_len(pkt);

	k_work_init(&pkt->work, tx_work_handler);
	if (!mcast) {
		ret = attach_fc_filter(net_can_dev, tx_ctx, pkt);
		if (ret < 0) {
			tx_report_err(pkt);
			return -EAGAIN;
		}

		tx_ctx->filter_id = ret;
	}

	ret = send_ff(pkt, len, mcast);
	if (ret != CAN_TX_OK) {
		NET_ERR("Failed to send FF [%d]", ret);
		tx_report_err(pkt);
		return -EIO;
	}

	if (!mcast) {
		z_add_timeout(&tx_ctx->timeout, tx_timeout,
			      z_ms_to_ticks(NET_CAN_BS));
		tx_ctx->state = NET_CAN_TX_STATE_WAIT_FC;
	} else {
		tx_ctx->state = NET_CAN_TX_STATE_SEND_CF;
		z_add_timeout(&tx_ctx->timeout, start_sending_cf,
			      z_ms_to_ticks(NET_CAN_FF_CF_TIME));
	}

	return 0;
}

static int canbus_send(struct net_if *iface, struct net_pkt *pkt)
{
	int comp_len;
	size_t pkt_len;
	bool mcast;
	int ret = 0;

	if (net_pkt_family(pkt) != AF_INET6) {
		return -EINVAL;
	}

	mcast = net_ipv6_is_addr_mcast(&NET_IPV6_HDR(pkt)->dst);

	comp_len = net_6lo_compress(pkt, true);
	if (comp_len < 0) {
		NET_ERR("IPHC failed [%d]", comp_len);
		return comp_len;
	}

	NET_INFO("IPv6 hdr compressed by %d bytes", comp_len);
	net_pkt_cursor_init(pkt);
	pkt_len = net_pkt_get_len(pkt);

	if (pkt_len > NET_CAN_DL - 1)  {
		k_sem_take(&tx_sem, K_FOREVER);
		ret = send_multiple_frames(pkt, pkt_len, mcast);

	} else {

		ret = send_single_frame(pkt, pkt_len, mcast);
		tx_finish(pkt);
	}

	return ret;
}

static inline int send_dad_request(struct device *net_can_dev,
				   struct net_can_lladdr *ll_addr)
{
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret;

	set_frame_datalength(&frame, 0);
	frame.rtr = 1;
	frame.id_type = CAN_EXTENDED_IDENTIFIER;
	frame.ext_id = addr_to_id(ll_addr->addr,
				  sys_rand32_get() & CAN_NET_IF_ADDR_MASK,
				  false);

	ret = api->send(net_can_dev, &frame, NULL, NULL);
	if (ret != CAN_TX_OK) {
		NET_ERR("Sending DAD request failed [%d]", ret);
		return -EIO;
	}

	return 0;
}

static void send_dad_resp_cb(u32_t err_flags, void *cb_arg)
{
	static u8_t fail_cnt;
	struct k_work *work = (struct k_work *)cb_arg;

	if (err_flags) {
		NET_ERR("Failed to send dad response [%u]", err_flags);
		if (err_flags != CAN_TX_BUS_OFF &&
		    fail_cnt < NET_CAN_DAD_SEND_RETRY) {
			k_work_submit_to_queue(&net_can_workq, work);
		}

		fail_cnt++;
	} else {
		fail_cnt = 0;
	}
}

static inline void send_dad_response(struct k_work *item)
{
	struct canbus_net_ctx *ctx = CONTAINER_OF(item, struct canbus_net_ctx,
						  dad_work);
	struct net_if *iface = ctx->iface;
	struct net_linkaddr *ll_addr = net_if_get_link_addr(iface);
	struct device *net_can_dev = net_if_get_device(iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret;

	set_frame_datalength(&frame, 0);
	frame.rtr = 0;
	frame.id_type = CAN_EXTENDED_IDENTIFIER;
	frame.ext_id = (NET_CAN_DAD_ADDR << CAN_NET_IF_ADDR_DEST_POS) |
			(UNALIGNED_GET((u16_t *) ll_addr->addr) <<
				CAN_NET_IF_ADDR_SRC_POS);

	ret = api->send(net_can_dev, &frame, send_dad_resp_cb, item);
	if (ret != CAN_TX_OK) {
		NET_ERR("Sending SF failed [%d]", ret);
	}
}


static inline void detach_filter(struct device *net_can_dev, int filter_id)
{
	const struct net_can_api *api = net_can_dev->driver_api;

	api->detach_filter(net_can_dev, filter_id);
}

static void dad_resp_cb(struct zcan_frame *frame, void *arg)
{
	struct k_sem *dad_sem = (struct k_sem *)arg;

	k_sem_give(dad_sem);
}

static inline int attach_dad_resp_filter(struct device *net_can_dev,
					 struct net_can_lladdr *ll_addr,
					 struct k_sem *dad_sem)
{
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
		.rtr_mask = 1,
		.ext_id_mask = CAN_EXT_ID_MASK
	};
	int filter_id;

	filter.ext_id = addr_to_id(NET_CAN_DAD_ADDR, ll_addr->addr, false);

	filter_id = api->attach_filter(net_can_dev, dad_resp_cb,
				       dad_sem, &filter);
	if (filter_id == CAN_NO_FREE_FILTER) {
		NET_ERR("Can't attach dad response filter.");
	}

	return filter_id;
}

static void dad_request_cb(struct zcan_frame *frame, void *arg)
{
	struct k_work *work = (struct k_work *)arg;

	k_work_submit_to_queue(&net_can_workq, work);
}

static inline int attach_dad_filter(struct device *net_can_dev,
				    struct net_can_lladdr *ll_addr,
				    struct k_work *dad_work)
{
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_REMOTEREQUEST,
		.rtr_mask = 1,
		.ext_id_mask = (CAN_NET_IF_ADDR_MASK << CAN_NET_IF_ADDR_SRC_POS)
	};
	int filter_id;

	filter.ext_id = addr_to_id(ll_addr->addr, 0, false);

	filter_id = api->attach_filter(net_can_dev, dad_request_cb,
				       dad_work, &filter);
	if (filter_id == CAN_NO_FREE_FILTER) {
		NET_ERR("Can't attach dad filter.");
	}

	return filter_id;
}

static inline int init_ll_addr(struct net_if *iface)
{
	struct canbus_net_ctx *ctx = net_if_l2_data(iface);
	struct device *net_can_dev = net_if_get_device(iface);
	int dad_resp_filter_id = CAN_NET_FILTER_NOT_SET;
	struct net_can_lladdr ll_addr;
	int ret;
	struct k_sem dad_sem;

#ifdef CONFIG_NET_L2_CAN_USE_FIXED_ADDR
	ll_addr.addr = CONFIG_NET_L2_CAN_FIXED_ADDR;
#else
	do {
		ll_addr.addr = sys_rand32_get() % (NET_CAN_MAX_ADDR + 1);
	} while (ll_addr.addr < NET_CAN_MIN_ADDR);
#endif

	dad_resp_filter_id = attach_dad_resp_filter(net_can_dev, &ll_addr,
						    &dad_sem);
	if (dad_resp_filter_id < 0) {
		return -EIO;
	}
	/*
	 * Attach this filter now to defend this address instantly.
	 * This filter is not called for own DAD because loopback is not
	 * enabled.
	 */
	ctx->dad_filter_id = attach_dad_filter(net_can_dev, &ll_addr,
					       &ctx->dad_work);
	if (ctx->dad_filter_id < 0) {
		ret = -EIO;
		goto dad_err;
	}

	k_sem_init(&dad_sem, 0, 1);
	ret = send_dad_request(net_can_dev, &ll_addr);
	if (ret) {
		ret = -EIO;
		goto dad_err;
	}

	ret = k_sem_take(&dad_sem, NET_CAN_DAD_TIMEOUT);
	detach_filter(net_can_dev, dad_resp_filter_id);
	dad_resp_filter_id = CAN_NET_FILTER_NOT_SET;

	if (ret != -EAGAIN) {
		NET_INFO("DAD failed");
		ret = -EAGAIN;
		goto dad_err;
	}

	ctx->ll_addr = sys_cpu_to_be16(ll_addr.addr);
	net_if_set_link_addr(iface, (u8_t *)&ctx->ll_addr, sizeof(ll_addr),
			     NET_LINK_CANBUS);
	return 0;

dad_err:
	if (ctx->dad_filter_id != CAN_NET_FILTER_NOT_SET) {
		detach_filter(net_can_dev, ctx->dad_filter_id);
		ctx->dad_filter_id = CAN_NET_FILTER_NOT_SET;
	}

	if (dad_resp_filter_id != CAN_NET_FILTER_NOT_SET) {
		detach_filter(net_can_dev, dad_resp_filter_id);
	}

	return ret;
}


void canbus_net_init(struct net_if *iface)
{
	struct canbus_net_ctx *ctx = net_if_l2_data(iface);
	u8_t thread_priority;
	int i;

	NET_DBG("Init CAN net interface");

	for (i = 0; i < ARRAY_SIZE(tx_ctx); i++) {
		tx_ctx[i].filter_id = CAN_NET_FILTER_NOT_SET;
		tx_ctx[i].state = NET_CAN_TX_STATE_UNUSED;
	}

	for (i = 0; i < ARRAY_SIZE(rx_ctx); i++) {
		rx_ctx[i].filter_id = CAN_NET_FILTER_NOT_SET;
		rx_ctx[i].state = NET_CAN_RX_STATE_UNUSED;
	}

	ctx->dad_filter_id = CAN_NET_FILTER_NOT_SET;
	ctx->iface = iface;
	k_work_init(&ctx->dad_work, send_dad_response);

	k_mutex_init(&tx_ctx_mtx);
	k_mutex_init(&rx_ctx_mtx);
	k_sem_init(&tx_sem, 1, INT_MAX);

	/* This work queue should have precedence over the tx stream
	 * TODO thread_priority = tx_tc2thread(NET_TC_TX_COUNT -1) - 1;
	 */
	thread_priority = 6;

	k_work_q_start(&net_can_workq, net_can_stack,
		       K_THREAD_STACK_SIZEOF(net_can_stack),
		       K_PRIO_COOP(thread_priority));
	k_thread_name_set(&net_can_workq.thread, "isotp_work");
	NET_DBG("Workq started. Thread ID: %p", &net_can_workq.thread);
}

static int canbus_net_enable(struct net_if *iface, bool state)
{
	struct device *net_can_dev = net_if_get_device(iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct canbus_net_ctx *ctx = net_if_l2_data(iface);
	int dad_retry_cnt, ret;

	NET_DBG("start to bring iface %p %s", iface, state ? "up" : "down");

	if (state) {
		for (dad_retry_cnt = CONFIG_NET_L2_CANBUS_DAD_RETRIES;
		     dad_retry_cnt; dad_retry_cnt--) {
			ret = init_ll_addr(iface);
			if (ret == 0) {
				break;
			} else if (ret == -EIO) {
				return -EIO;
			}
		}
	} else {
		if (ctx->dad_filter_id != CAN_NET_FILTER_NOT_SET) {
			detach_filter(net_can_dev, ctx->dad_filter_id);
		}
	}

	ret = api->enable(net_can_dev, state);
	if (!ret) {
		NET_DBG("Iface %p is up", iface);
	}
	return ret;
}

static enum net_l2_flags canbus_net_flags(struct net_if *iface)
{
	return NET_L2_MULTICAST;
}

NET_L2_INIT(CANBUS_L2, canbus_recv, canbus_send, canbus_net_enable,
	    canbus_net_flags);
