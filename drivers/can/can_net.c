/*
 * Copyright (c) 2019 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <net/can.h>
#include <net/net_pkt.h>

#include <logging/log.h>
LOG_MODULE_REGISTER(net_can, CONFIG_CAN_NET_LOG_LEVEL);

#define CAN_NET_FILTER_NOT_SET -1

struct net_can_context {
	struct device *can_dev;
	struct net_if *iface;
	int rcv_filter_id;
	int mcast_filter_id;
};

static inline u8_t get_frame_datalength(struct zcan_frame *frame)
{
	/* TODO: Needs update when CAN FD support is added*/
	return frame->dlc;
}

static inline u16_t get_can_lladdr_src(struct zcan_frame *frame)
{
	return (frame->ext_id >> CAN_NET_IF_ADDR_SRC_POS) &
		     CAN_NET_IF_ADDR_MASK;
}

static inline u16_t get_can_lladdr_dest(struct zcan_frame *frame)
{
	return (frame->ext_id >> CAN_NET_IF_ADDR_DEST_POS) &
		     CAN_NET_IF_ADDR_MASK;
}

static inline void set_lladdr(struct net_pkt *pkt, struct zcan_frame *frame)
{
	struct net_buf *buf = pkt->buffer;

	net_pkt_lladdr_src(pkt)->addr = buf->data;
	net_pkt_lladdr_src(pkt)->len = sizeof(struct net_can_lladdr);
	net_pkt_lladdr_src(pkt)->type = NET_LINK_CANBUS;
	net_buf_add_be16(buf, get_can_lladdr_src(frame));
	net_buf_pull(buf, sizeof(u16_t));

	net_pkt_lladdr_dst(pkt)->addr = buf->data;
	net_pkt_lladdr_dst(pkt)->len = sizeof(struct net_can_lladdr);
	net_pkt_lladdr_dst(pkt)->type = NET_LINK_CANBUS;
	net_buf_add_be16(buf, get_can_lladdr_dest(frame));
	net_buf_pull(buf, sizeof(u16_t));

	net_pkt_cursor_init(pkt);
}

static void net_can_iface_init(struct net_if *iface)
{
	struct device *dev = net_if_get_device(iface);
	struct net_can_context *ctx = dev->driver_data;

	ctx->iface = iface;

	NET_DBG("Init CAN network interface %p dev %p", iface, dev);

	canbus_net_init(iface);
}

static int net_can_send(struct device *dev, const struct zcan_frame *frame,
			can_tx_callback_t cb, void *cb_arg)
{
	struct net_can_context *ctx = dev->driver_data;

	NET_ASSERT(frame->id_type == CAN_EXTENDED_IDENTIFIER);
	return can_send(ctx->can_dev, frame, K_FOREVER, cb, cb_arg);
}

static void net_can_rcv(struct zcan_frame *frame, void *arg)
{
	struct net_can_context *ctx = (struct net_can_context *)arg;
	size_t pkt_size = 2 * sizeof(struct net_can_lladdr) +
			  get_frame_datalength(frame);
	struct net_pkt *pkt;
	int ret;

	NET_DBG("Frame with ID 0x%x received", frame->ext_id);
	pkt = net_pkt_rx_alloc_with_buffer(ctx->iface, pkt_size, AF_UNSPEC, 0,
					   K_NO_WAIT);
	if (!pkt) {
		LOG_ERR("Failed to obtain net_pkt with size of %d", pkt_size);
		goto drop;
	}

	pkt->can_rx_ctx = NULL;
	set_lladdr(pkt, frame);
	ret = net_pkt_write(pkt, frame->data, get_frame_datalength(frame));
	if (ret) {
		LOG_ERR("Failed to append frame data to net_pkt");
		goto drop;
	}

	ret = net_recv_data(ctx->iface, pkt);
	if (ret < 0) {
		LOG_ERR("Packet dropped by NET stack");
		goto drop;
	}

	return;

drop:
	NET_INFO("pkt dropped");
	if (pkt) {
		net_pkt_unref(pkt);
	}
}

static int attach_filter(struct device *dev, can_rx_callback_t cb, void *cb_arg,
			 const struct zcan_filter *filter)
{
	struct net_can_context *ctx = dev->driver_data;

	return can_attach_isr(ctx->can_dev, cb, cb_arg, filter);
}

static void detach_filter(struct device *dev, int filter_id)
{
	struct net_can_context *ctx = dev->driver_data;

	if (filter_id >= 0) {
		can_detach(ctx->can_dev, filter_id);
	}
}

static inline int attach_unicast_filter(struct net_can_context *ctx)
{
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
		.rtr_mask = 1,
		.ext_id_mask = CAN_NET_IF_ADDR_DEST_MASK
	};
	const u8_t *link_addr = net_if_get_link_addr(ctx->iface)->addr;
	const u16_t dest = sys_be16_to_cpu(UNALIGNED_GET((u16_t *) link_addr));
	int filter_id;

	filter.ext_id = (dest << CAN_NET_IF_ADDR_DEST_POS);

	filter_id = can_attach_isr(ctx->can_dev, net_can_rcv,
				   ctx, &filter);
	if (filter_id == CAN_NET_FILTER_NOT_SET) {
		NET_ERR("Can't attach FF filter.");
		return CAN_NET_FILTER_NOT_SET;
	} else {
		NET_DBG("Attached FF filter %d.", filter_id);
	}

	return filter_id;
}

static inline int attach_mcast_filter(struct net_can_context *ctx)
{
	struct zcan_filter filter = {
		.id_type = CAN_EXTENDED_IDENTIFIER,
		.rtr = CAN_DATAFRAME,
		.rtr_mask = 1,
		.ext_id_mask = CAN_NET_IF_ADDR_DEST_MASK
	};
	int filter_id;

	filter.ext_id = (NET_CAN_MULTICAST_ADDR << CAN_NET_IF_ADDR_DEST_POS);

	filter_id = can_attach_isr(ctx->can_dev, net_can_rcv,
				   ctx, &filter);
	if (filter_id == CAN_NET_FILTER_NOT_SET) {
		NET_ERR("Can't attach multicast filter.");
		return CAN_NET_FILTER_NOT_SET;
	} else {
		NET_DBG("Attached multicast filter %d.", filter_id);
	}

	return filter_id;
}

static int enable(struct device *dev, bool enable)
{
	struct net_can_context *ctx = dev->driver_data;

	if (enable) {
		if (ctx->rcv_filter_id == CAN_NET_FILTER_NOT_SET) {
			ctx->rcv_filter_id = attach_unicast_filter(ctx);
			if (ctx->rcv_filter_id < 0) {
				return -EIO;
			}
		}

		if (ctx->mcast_filter_id == CAN_NET_FILTER_NOT_SET) {
			ctx->mcast_filter_id = attach_mcast_filter(ctx);
			if (ctx->mcast_filter_id < 0) {
				can_detach(ctx->can_dev, ctx->rcv_filter_id);
				return -EIO;
			}
		}
	} else {
		if (ctx->rcv_filter_id != CAN_NET_FILTER_NOT_SET) {
			can_detach(ctx->can_dev, ctx->rcv_filter_id);
		}

		if (ctx->mcast_filter_id != CAN_NET_FILTER_NOT_SET) {
			can_detach(ctx->can_dev, ctx->mcast_filter_id);
		}
		
	}

	return 0;
}

static struct net_can_api net_can_api_inst = {
	.iface_api.init = net_can_iface_init,

	.send = net_can_send,
	.attach_filter = attach_filter,
	.detach_filter = detach_filter,
	.enable = enable,
};

static int net_can_init(struct device *dev)
{
	struct device *can_dev = device_get_binding(DT_CAN_1_NAME);
	struct net_can_context *ctx = dev->driver_data;

	ctx->rcv_filter_id = CAN_NET_FILTER_NOT_SET;
	ctx->mcast_filter_id = CAN_NET_FILTER_NOT_SET;

	if (!can_dev) {
		NET_ERR("Can't get binding to CAN device %s", DT_CAN_1_NAME);
		return -EIO;
	}

	NET_DBG("Init net CAN device %p (%s) for dev %p (%s)",
		dev, dev->config->name, can_dev, can_dev->config->name);

	ctx->can_dev = can_dev;

	return 0;
}


static struct net_can_context net_can_context_1;

NET_DEVICE_INIT(net_can_stm32_1, CONFIG_CAN_NET_NAME, net_can_init,
		&net_can_context_1, NULL,
		CONFIG_CAN_NET_INIT_PRIORITY,
		&net_can_api_inst,
		CANBUS_L2, NET_L2_GET_CTX_TYPE(CANBUS_L2), NET_CAN_DL);
