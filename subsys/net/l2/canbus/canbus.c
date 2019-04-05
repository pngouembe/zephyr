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
	struct can_net_isotp_tx_ctx *ctx = pkt->can_tx_ctx;

	if (ctx->state != NET_CAN_TX_STATE_RESET) {
		z_abort_timeout(&ctx->timeout);
	}

	free_tx_ctx(ctx);
	net_pkt_unref(pkt);
	k_sem_give(&tx_sem);
}

static void rx_finish(struct net_pkt *pkt)
{
	struct can_net_isotp_rx_ctx *ctx = pkt->can_rx_ctx;

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

static inline void cpy_lladdr(struct net_pkt *dst, struct net_pkt *src)
{
	struct net_buf *buf = dst->buffer;

	net_pkt_lladdr_src(dst)->addr =  buf->data;
	net_pkt_lladdr_src(dst)->len = net_pkt_lladdr_src(src)->len;
	net_pkt_lladdr_src(dst)->type = net_pkt_lladdr_src(src)->type;
	net_buf_add_mem(buf, net_pkt_lladdr_src(src)->addr,
			net_pkt_lladdr_src(src)->len);
	net_buf_pull(buf, net_pkt_lladdr_src(src)->len);

	net_pkt_lladdr_dst(dst)->addr = buf->data;
	net_pkt_lladdr_dst(dst)->len = net_pkt_lladdr_dst(src)->len;
	net_pkt_lladdr_dst(dst)->type = net_pkt_lladdr_dst(src)->type;
	net_buf_add_mem(buf, net_pkt_lladdr_dst(src)->addr,
			net_pkt_lladdr_dst(src)->len);
	net_buf_pull(buf, net_pkt_lladdr_dst(src)->len);

	net_pkt_cursor_init(dst);
}

static u16_t get_lladdr(struct net_linkaddr *net_lladdr)
{
	NET_ASSERT(net_lladdr->len == sizeof(u16_t));
	return sys_be16_to_cpu(UNALIGNED_GET((u16_t *)net_lladdr->addr));
}


static u16_t get_src_lladdr(struct net_pkt *pkt)
{
	return get_lladdr(net_pkt_lladdr_src(pkt));
}

static u16_t get_dest_lladdr(struct net_pkt *pkt)
{
	return get_lladdr(net_pkt_lladdr_dst(pkt));
}

static inline bool dest_is_mcast(struct net_pkt *pkt)
{
	return (get_dest_lladdr(pkt) == NET_CAN_MULTICAST_ADDR);
}

static struct can_net_isotp_rx_ctx *get_rx_ctx(u8_t state, u16_t src_addr)
{
	int i;
	struct can_net_isotp_rx_ctx *ret = NULL;

	k_mutex_lock(&rx_ctx_mtx, K_FOREVER);
	for (i = 0; i < ARRAY_SIZE(rx_ctx); i++) {
		if (rx_ctx[i].state == state) {
			if (state == NET_CAN_RX_STATE_UNUSED) {
				rx_ctx[i].state = NET_CAN_RX_STATE_RESET;
				z_init_timeout(&rx_ctx[i].timeout, rx_timeout);
				ret = &rx_ctx[i];
				break;
			}

			if (get_src_lladdr(rx_ctx[i].pkt) == src_addr) {
				ret = &rx_ctx[i];
				break;
			}
		}
	}

	k_mutex_unlock(&rx_ctx_mtx);
	return ret;
}

static struct can_net_isotp_tx_ctx *get_tx_ctx(u8_t state, u16_t dest_addr)
{
	int i;
	struct can_net_isotp_tx_ctx *ret = NULL;

	k_mutex_lock(&tx_ctx_mtx, K_FOREVER);
	for (i = 0; i < ARRAY_SIZE(tx_ctx); i++) {
		if (tx_ctx[i].state == state) {
			if (state == NET_CAN_TX_STATE_UNUSED) {
				tx_ctx[i].state = NET_CAN_TX_STATE_RESET;
				z_init_timeout(&tx_ctx[i].timeout, tx_timeout);
				ret = &tx_ctx[i];
				break;
			}

			if (get_dest_lladdr(tx_ctx[i].pkt) == dest_addr) {
				ret = &tx_ctx[i];
				break;
			}
		}
	}

	k_mutex_unlock(&tx_ctx_mtx);
	return ret;
}

static inline u32_t receive_get_ff_length(struct net_pkt *pkt)
{
	u32_t len;
	u16_t len_u12;
	int ret;

	ret = net_pkt_read_be16(pkt, &len_u12);
	if (ret < 0) {
		NET_ERR("Can't read length");
	}

	len = len_u12 & 0x0FFF;

	/* Jumbo packet (32 bit length)*/
	if (!len) {
		ret = net_pkt_read_be32(pkt, &len);
	}
	if (ret < 0) {
		NET_ERR("Can't 32 bit length");
	}

	return len;
}

static inline size_t get_sf_length(struct net_pkt *pkt)
{
	u8_t pci;
	size_t len;

	pci = net_buf_pull_u8(pkt->frags);
	len = pci & NET_CAN_PCI_SF_DL_MASK;

	/*Single frame with CAN_DL > 8*/
	if (len == 0) {
		len = net_buf_pull_u8(pkt->frags);
	}

	return len;
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

static inline u32_t addr_to_id(u16_t dest, u16_t src)
{
	return (dest << CAN_NET_IF_ADDR_DEST_POS) |
	       (src  << CAN_NET_IF_ADDR_SRC_POS);
}

static void set_frame_addr(struct zcan_frame *frame,
			   const struct net_can_lladdr *dest,
			   const struct net_can_lladdr *src)
{
	frame->id_type = CAN_EXTENDED_IDENTIFIER;
	frame->rtr = CAN_DATAFRAME;

	frame->ext_id = addr_to_id(dest->addr, src->addr);
}


static void set_frame_addr_pkt(struct zcan_frame *frame, struct net_pkt *pkt,
			       bool mcast)
{
	struct net_can_lladdr src_addr, dest_addr;

	dest_addr.addr = mcast ? NET_CAN_MULTICAST_ADDR : get_dest_lladdr(pkt);
	src_addr.addr = get_lladdr(net_if_get_link_addr(pkt->iface));

	set_frame_addr(frame, &dest_addr, &src_addr);
}

static void fc_send_cb(u32_t err_flags, void *arg)
{
	if (err_flags) {
		NET_ERR("Sending FC frame failed: %d", err_flags);
	}
}

static int send_fc(struct device *net_can_dev, struct net_can_lladdr *dest,
		   struct net_can_lladdr *src, u8_t fs)
{
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame = {
		.id_type  = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
	};
	int ret;

	NET_ASSERT(!(fs & NET_CAN_PCI_TYPE_MASK));

	set_frame_addr(&frame, dest, src);

	frame.data[0] = NET_CAN_PCI_TYPE_FC | fs;
	/* Block size of 0. This means that all data is sent without waiting for
	 * additional FC frames
	 */
	frame.data[1] = 0;
	/*STmin*/
	frame.data[2] = NET_CAN_STMIN;
	set_frame_datalength(&frame, 3);

	NET_DBG("Sending FC to ID: 0x%08x", frame.ext_id);
	ret = api->send(net_can_dev, &frame, fc_send_cb, NULL);
	return ret;
}

static enum net_verdict process_cf_data(struct net_pkt *frag_pkt,
			    struct can_net_isotp_rx_ctx *ctx)
{
	struct net_pkt *pkt = ctx->pkt;
	size_t data_len = net_pkt_get_len(frag_pkt) - 1;
	u8_t pci;
	int ret;

	z_abort_timeout(&ctx->timeout);

	pci = net_buf_pull_u8(frag_pkt->frags);

	if ((pci & NET_CAN_PCI_SN_MASK) != ctx->sn) {
		NET_ERR("Sequence number missmatch. Expect %u, got %u",
			ctx->sn, pci & NET_CAN_PCI_SN_MASK);
		goto err;
	}

	ctx->sn++;

	if (data_len > ctx->rem_len) {
		NET_DBG("Remove padding of %d bytes", data_len - ctx->rem_len);
		data_len = ctx->rem_len;
	}

	net_pkt_cursor_init(frag_pkt);
	NET_DBG("Appending CF data to pkt (%d bytes)", data_len);
	ret = net_pkt_copy(pkt, frag_pkt, data_len);
	if (ret < 0) {
		NET_ERR("Failed to write data to pkt [%d]", ret);
		goto err;
	}

	net_pkt_unref(frag_pkt);
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

	return NET_OK;
err:
	rx_report_err(pkt);
	return NET_DROP;
}

static enum net_verdict process_cf(struct net_pkt *pkt)
{
	struct can_net_isotp_rx_ctx *rx_ctx;

	rx_ctx = get_rx_ctx(NET_CAN_RX_STATE_CF, get_src_lladdr(pkt));
	if (!rx_ctx) {
		NET_INFO("Got CF but can't find a CTX that is waiting for it");
		net_pkt_unref(pkt);
		return NET_DROP;
	}

	return process_cf_data(pkt, rx_ctx);
}

static enum net_verdict process_ff(struct net_pkt *pkt)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	struct can_net_isotp_rx_ctx *rx_ctx = NULL;
	struct net_pkt *new_pkt = NULL;
	int ret;
	struct net_can_lladdr src, dest;
	u32_t msg_len;
	u8_t data_len;
	bool mcast;

	mcast = dest_is_mcast(pkt);
	src.addr = get_src_lladdr(pkt);
	dest.addr = get_dest_lladdr(pkt);


	net_pkt_cursor_init(pkt);
	msg_len = receive_get_ff_length(pkt);
	new_pkt = net_pkt_rx_alloc_with_buffer(pkt->iface,
					       msg_len + 2 * sizeof(struct net_can_lladdr),
					       AF_INET6, 0,
					       NET_CAN_ALLOC_TIMEOUT);
	if (!new_pkt) {
		NET_ERR("Failed to obtain net_pkt with size of %d",
			msg_len + 2 * sizeof(struct net_can_lladdr));

		if (!mcast) {
			send_fc(net_can_dev, &src, &dest, NET_CAN_PCI_FS_OVFLW);
		}

		goto err;
	}

	rx_ctx = get_rx_ctx(NET_CAN_RX_STATE_UNUSED, 0);
	if (!rx_ctx) {
		NET_ERR("No rx context left");

		if (!mcast) {
			send_fc(net_can_dev, &src, &dest, NET_CAN_PCI_FS_OVFLW);
		}

		goto err;
	}

	rx_ctx->pkt = new_pkt;
	new_pkt->can_rx_ctx = rx_ctx;
	cpy_lladdr(new_pkt, pkt);

	rx_ctx->sn = 1;
	data_len = net_pkt_remaining_data(pkt);
	ret = net_pkt_copy(new_pkt, pkt, data_len);
	if (ret) {
		NET_ERR("Failed to write to pkt [%d]", ret);
		goto err;
	}

	rx_ctx->rem_len = msg_len - data_len;
	net_pkt_unref(pkt);

	if (!mcast) {
		/* switch src and dest because we are answering */
		ret = send_fc(net_can_dev, &src, &dest, NET_CAN_PCI_FS_CTS);
		if (ret) {
			NET_ERR("Failed to send FC CTS.");
			rx_report_err(new_pkt);
			return NET_OK;
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

static enum net_verdict process_sf(struct net_pkt *pkt)
{
	size_t data_len;
	size_t pkt_len;

	net_pkt_set_family(pkt, AF_INET6);

	data_len = get_sf_length(pkt);
	pkt_len = net_pkt_get_len(pkt);

	if (data_len > pkt_len) {
		NET_ERR("SF datalen > pkt size");
		return NET_DROP;
	}
	if (pkt_len != data_len) {
		NET_DBG("Remove padding (%d byte)", pkt_len - data_len);
		net_pkt_update_length(pkt, data_len);
	}

	return finish_pkt(pkt);
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

	set_frame_addr_pkt(&frame, pkt, ctx->is_mcast);

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

static enum net_verdict process_fc_data(struct can_net_isotp_tx_ctx *ctx,
			    struct net_pkt *pkt)
{
	struct net_buf *buf = pkt->frags;
	u8_t pci;

	pci = net_buf_pull_u8(buf);

	switch (pci & NET_CAN_PCI_FS_MASK) {
	case NET_CAN_PCI_FS_CTS:
		if (net_buf_frags_len(buf) != 2) {
			NET_ERR("Frame length error for CTS");
			tx_report_err(pkt);
			return NET_DROP;
		}
		ctx->state = NET_CAN_TX_STATE_SEND_CF;
		ctx->wft = 0;
		ctx->opts.bs = net_buf_pull_u8(buf);
		ctx->opts.stmin = net_buf_pull_u8(buf);
		ctx->act_block_nr = ctx->opts.bs;
		z_abort_timeout(&ctx->timeout);
		NET_DBG("Got CTS. BS: %d, STmin: %d. CTX: %p",
			ctx->opts.bs, ctx->opts.stmin, ctx);
		net_pkt_unref(pkt);
		return NET_OK;
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
		return NET_OK;
	case NET_CAN_PCI_FS_OVFLW:
		NET_ERR("Got overflow FC frame. CTX: %p", ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
		return NET_OK;
	default:
		NET_ERR("Invalid Frame Status. CTX: %p", ctx);
		ctx->state = NET_CAN_TX_STATE_ERR;
		break;
	}

	return NET_DROP;
}

static enum net_verdict process_fc(struct net_pkt *pkt)
{
	struct can_net_isotp_tx_ctx *tx_ctx;
	u16_t src_addr = get_src_lladdr(pkt);
	enum net_verdict ret;

	tx_ctx = get_tx_ctx(NET_CAN_TX_STATE_WAIT_FC, src_addr);
	if (!tx_ctx) {
		NET_INFO("Got FC frame from 0x%04x but can't find any "
			 "CTX waiting for it", src_addr);
		net_pkt_unref(pkt);
		return NET_DROP;
	}

	ret = process_fc_data(tx_ctx, pkt);
	if (ret == NET_OK) {
		k_work_submit_to_queue(&net_can_workq, &tx_ctx->pkt->work);
	}

	return ret;
}

static inline int send_ff(struct net_pkt *pkt, size_t len, bool mcast)
{
	struct device *net_can_dev = net_if_get_device(pkt->iface);
	const struct net_can_api *api = net_can_dev->driver_api;
	struct zcan_frame frame;
	int ret, index = 0;

	set_frame_addr_pkt(&frame, pkt, mcast);
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

	set_frame_addr_pkt(&frame, pkt, mcast);

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
	int ret;

	tx_ctx = get_tx_ctx(NET_CAN_TX_STATE_UNUSED, 0);

	if (!tx_ctx) {
		NET_ERR("No tx context left");
		k_sem_give(&tx_sem);
		return -EAGAIN;
	}

	tx_ctx->pkt = pkt;
	pkt->can_tx_ctx = tx_ctx;
	tx_ctx->is_mcast = mcast;
	tx_ctx->rem_len = net_pkt_get_len(pkt);

	k_work_init(&pkt->work, tx_work_handler);

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

static enum net_verdict process_frame(struct net_pkt *pkt)
{
	enum net_verdict ret = NET_DROP;
	u8_t pci_type;

	net_pkt_cursor_init(pkt);
	ret = net_pkt_read_u8(pkt, &pci_type);
	if (ret < 0) {
		NET_ERR("Can't read PCI");
	}
	pci_type = (pci_type & NET_CAN_PCI_TYPE_MASK) >> NET_CAN_PCI_TYPE_POS;

	switch (pci_type) {
	case NET_CAN_PCI_SF:
		ret = process_sf(pkt);
		break;
	case NET_CAN_PCI_FF:
		ret = process_ff(pkt);
		break;
	case NET_CAN_PCI_CF:
		ret = process_cf(pkt);
		break;
	case NET_CAN_PCI_FC:
		ret = process_fc(pkt);
		break;
	default:
		NET_ERR("Unknown PCI number %u", pci_type);
		break;
	}

	return ret;
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
		ret = process_frame(pkt);
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
				  sys_rand32_get() & CAN_NET_IF_ADDR_MASK);

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

	filter.ext_id = addr_to_id(NET_CAN_DAD_ADDR, ll_addr->addr);

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

	filter.ext_id = addr_to_id(ll_addr->addr, 0);

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
		tx_ctx[i].state = NET_CAN_TX_STATE_UNUSED;
	}

	for (i = 0; i < ARRAY_SIZE(rx_ctx); i++) {
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
