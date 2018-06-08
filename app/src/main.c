/*
 * Copyright (c) 2016 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#if 1
#define SYS_LOG_DOMAIN "coap-server"
#define SYS_LOG_LEVEL SYS_LOG_LEVEL_DEBUG
#define NET_LOG_ENABLED 1
#endif

#include <errno.h>
#include <misc/printk.h>

#include <zephyr.h>
#include <device.h>
#include <pwm.h>
#include <gpio.h>
#include <uart.h>
#include <dma.h>

#include <misc/byteorder.h>
#include <misc/util.h>
#include <net/buf.h>
#include <net/net_pkt.h>
#include <net/net_ip.h>
#include <net/udp.h>

#include <net/coap.h>
#include <net/coap_link_format.h>
#include <stdlib.h>
#include <ctype.h>

#include "net_private.h"

#define PWM_FREQ 2000
#define PULSE_UPPER_BOUND 75
#define PULSE_LOWER_BOUND 40
#define PWM_CHANNEL_RAIL1 1
#define FW_PIN 8
#define RW_PIN 9

#define MY_COAP_PORT 5683

#define STACKSIZE 2000

/* FIXME */
#define BLOCK_WISE_TRANSFER_SIZE_GET 2048

#define ALL_NODES_LOCAL_COAP_MCAST \
	{ { { 0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xfd } } }

#define MY_IP6ADDR \
	{ { { 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x1 } } }

#define NUM_OBSERVERS 3

#define NUM_PENDINGS 3

/* block option helper */
#define GET_BLOCK_NUM(v)	((v) >> 4)
#define GET_BLOCK_SIZE(v)	(((v) & 0x7))
#define GET_MORE(v)		(!!((v) & 0x08))

static struct net_context *context;

static const u8_t plain_text_format;

static struct coap_observer observers[NUM_OBSERVERS];

static struct coap_pending pendings[NUM_PENDINGS];

static struct net_context *context;

struct k_delayed_work retransmit_work;

struct device* pwm_dev;
struct device* gpio_dev;
struct device* uart6_dev;

u32_t pwm_period;

u8_t uart_buffer[2];

s16_t speed = 0;
int reverse_allowed = 1;

static void get_from_ip_addr(struct coap_packet *cpkt,
			     struct sockaddr_in6 *from)
{
	struct net_udp_hdr hdr, *udp_hdr;

	udp_hdr = net_udp_get_hdr(cpkt->pkt, &hdr);
	if (!udp_hdr) {
		return;
	}

	net_ipaddr_copy(&from->sin6_addr, &NET_IPV6_HDR(cpkt->pkt)->src);
	from->sin6_port = udp_hdr->src_port;
	from->sin6_family = AF_INET6;
}

static int well_known_core_get(struct coap_resource *resource,
			       struct coap_packet *request)
{
	struct coap_packet response;
	struct sockaddr_in6 from;
	struct net_pkt *pkt;
	struct net_buf *frag;
	int r;

	NET_DBG("");

	pkt = net_pkt_get_tx(context, K_FOREVER);
	frag = net_pkt_get_data(context, K_FOREVER);

	net_pkt_frag_add(pkt, frag);

	r = coap_well_known_core_get(resource, request, &response, pkt);
	if (r < 0) {
		net_pkt_unref(response.pkt);
		return r;
	}

	get_from_ip_addr(request, &from);
	r = net_context_sendto(response.pkt, (const struct sockaddr *)&from,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		net_pkt_unref(response.pkt);
	}

	return r;
}

static void payload_dump(const char *s, struct net_buf *frag,
			 u16_t offset, u16_t len)
{
	printk("payload message = %s [%u]\n", s, len);

	while (frag) {
		_hexdump(frag->data + offset, frag->len - offset, 0);
		frag = frag->frags;
		offset = 0;
	}
}

static int is_number(char* str, int len)
{
	char* char_p = str;
	int remain = len;

	if(*char_p == '-' || *char_p == '+') {
		remain --;
		char_p ++;
	}

	for(; *char_p && remain; remain--, char_p ++)
	{
		if(!isdigit(*char_p)) {
			return 0;
		}
	}

	return 1;
}

static const char * const speed_path[] = { "speed", NULL };
static const char * const forbid_reverse_path[] = { "forbidRev", NULL };
static const char * const speed_attributes[] = {
	"title=\"speed\"",
	"rt=output-voltage",
	NULL };
static const char * const forbid_reverse_attributes[] = {
	"title=\"forbid-reverse\"",
	NULL };

static int resource_put(struct coap_resource *resource,
		    struct coap_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct coap_packet response;
	u8_t code, type, tkl;
	u8_t resp_code = COAP_RESPONSE_CODE_BAD_REQUEST;
	u8_t token[8];
	u16_t id;
	int r;

	struct net_buf *payloadfrag;

	u16_t offset;
	u16_t len;

	/* TODO: Check for payload, empty payload is an error case. */

	get_from_ip_addr(request, &from);
	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	payloadfrag = coap_packet_get_payload(request, &offset, &len);
	if (!payloadfrag && len == 0xffff) {
		NET_ERR("Invalid payload");
		return -EINVAL;
	} else if (!payloadfrag && !len) {
		NET_INFO("Packet without payload\n");
		goto next;
	}

	payload_dump("put_payload", payloadfrag, offset, len);
	*(payloadfrag->data + offset + len) = '\0';

	if (resource->path == speed_path) {
		int speed_tmp = 0;
		u32_t pulse = 0;
		u32_t speed_abs;

		if (!is_number(payloadfrag->data + offset, len)) {
			printk("Not a number\n");
			resp_code = COAP_RESPONSE_CODE_BAD_REQUEST;
			goto next;
		}
		
		speed_tmp = atoi(payloadfrag->data + offset);
		if (speed_tmp < 0 && !reverse_allowed) {
			resp_code = COAP_RESPONSE_CODE_FORBIDDEN;
			goto next;
		}
			
		printk("got speed: %d\n", speed_tmp);
		if ((s16_t)speed_tmp > 100 || (s16_t)speed_tmp < -100) {
			printk("Speed must be <= 100");
			resp_code = COAP_RESPONSE_CODE_BAD_REQUEST;
			goto next;
		}

		speed = (s16_t)speed_tmp;
		speed_abs = speed < 0 ? -speed : speed;

		pulse = (pwm_period * (speed_abs * (PULSE_UPPER_BOUND - PULSE_LOWER_BOUND) + PULSE_LOWER_BOUND * 100)) / (100 * 100);
		printk("period: %d, pulse: %d\n", pwm_period, pulse);
		pwm_pin_set_cycles(pwm_dev, PWM_CHANNEL_RAIL1, pwm_period, pulse);

		if(speed > 0) {
			gpio_pin_write(gpio_dev, FW_PIN, 1);
			gpio_pin_write(gpio_dev, RW_PIN, 0);
		} else if (speed < 0) {
			gpio_pin_write(gpio_dev, FW_PIN, 0);
			gpio_pin_write(gpio_dev, RW_PIN, 1);
		} else {
			gpio_pin_write(gpio_dev, FW_PIN, 0);
			gpio_pin_write(gpio_dev, RW_PIN, 0);
		}

		resp_code = COAP_RESPONSE_CODE_CHANGED;

	} else if (resource->path == forbid_reverse_path) {
		char* payload = payloadfrag->data + offset;

		if (!strncmp(payload, "allow", len) || !strncmp(payload, "0", len)) {
			reverse_allowed = 1;
		}
		else if (!strncmp(payload, "forbid", len) || !strncmp(payload, "1", len)) {
			reverse_allowed = 0;
		}
		else {
			resp_code = COAP_RESPONSE_CODE_BAD_REQUEST;
		}
	}
	

next:
	pkt = net_pkt_get_tx(context, K_FOREVER);
	frag = net_pkt_get_data(context, K_FOREVER);

	net_pkt_frag_add(pkt, frag);

	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
	}

	r = coap_packet_init(&response, pkt, 1, type,
			     tkl, (u8_t *)token,
			     resp_code, id);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	return net_context_sendto(pkt, (const struct sockaddr *)&from,
				  sizeof(struct sockaddr_in6),
				  NULL, 0, NULL, NULL);
}

static int resource_get(struct coap_resource *resource,
			 struct coap_packet *request)
{
	struct net_pkt *pkt;
	struct net_buf *frag;
	struct sockaddr_in6 from;
	struct coap_packet response;
	u8_t token[8];
	u8_t payload[40], code, type;
	u16_t id;
	u8_t tkl;
	int r;

	get_from_ip_addr(request, &from);
	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	pkt = net_pkt_get_tx(context, K_FOREVER);
	frag = net_pkt_get_data(context, K_FOREVER);

	net_pkt_frag_add(pkt, frag);

	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
	}

	r = coap_packet_init(&response, pkt, 1, type,
			     tkl, (u8_t *)token,
			     COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = coap_packet_append_option(&response, COAP_OPTION_CONTENT_FORMAT,
				      &plain_text_format,
				      sizeof(plain_text_format));
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = coap_packet_append_payload_marker(&response);
	if (r) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	if (resource->path == speed_path) {
		r = snprintk((char *) payload, sizeof(payload), "Speed: %hd\n", speed);
		if (r < 0) {
			net_pkt_unref(pkt);
			return -EINVAL;
		}
	}
	else if (resource->path == forbid_reverse_path) {
		char* ret_str = reverse_allowed ? "allowed" : "forbidden";
		memcpy(payload, ret_str, strlen(ret_str) + 1);
	}
	else
	{
		printk("WTF?\n");
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	r = coap_packet_append_payload(&response, (u8_t *)payload, strlen(payload));
	if (r < 0) {
		net_pkt_unref(pkt);
		return -EINVAL;
	}

	return net_context_sendto(pkt, (const struct sockaddr *)&from,
				  sizeof(struct sockaddr_in6),
				  NULL, 0, NULL, NULL);
}


static struct coap_resource resources[] = {
	{ .get = well_known_core_get,
	  .path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{ .get = resource_get,
	  .put = resource_put,
	  .path = speed_path,
	  .user_data = &((struct coap_core_metadata) {
			  .attributes = speed_attributes,
			}),
	},
	{ .get = resource_get,
	  .put = resource_put,
	  .path = forbid_reverse_path,
	  .user_data = &((struct coap_core_metadata) {
			  .attributes = forbid_reverse_attributes,
			}),
	},
	{ },
};


static struct coap_resource *find_resouce_by_observer(
	struct coap_resource *resources, struct coap_observer *o)
{
	struct coap_resource *r;

	for (r = resources; r && r->path; r++) {
		sys_snode_t *node;

		SYS_SLIST_FOR_EACH_NODE(&r->observers, node) {
			if (&o->list == node) {
				return r;
			}
		}
	}

	return NULL;
}

static void udp_receive(struct net_context *context,
			struct net_pkt *pkt,
			int status,
			void *user_data)
{
	struct coap_packet request;
	struct coap_pending *pending;
	struct sockaddr_in6 from;
	struct coap_option options[16] = { 0 };
	u8_t opt_num = 16;
	int r;

	r = coap_packet_parse(&request, pkt, options, opt_num);
	if (r < 0) {
		NET_ERR("Invalid data received (%d)\n", r);
		net_pkt_unref(pkt);
		return;
	}

	get_from_ip_addr(&request, &from);
	pending = coap_pending_received(&request, pendings,
					NUM_PENDINGS);
	if (!pending) {
		goto not_found;
	}

	if (coap_header_get_type(&request) == COAP_TYPE_RESET) {
		struct coap_resource *r;
		struct coap_observer *o;

		o = coap_find_observer_by_addr(observers, NUM_OBSERVERS,
					       (struct sockaddr *)&from);
		if (!o) {
			NET_ERR("Observer not found\n");
			goto not_found;
		}

		r = find_resouce_by_observer(resources, o);
		if (!r) {
			NET_ERR("Observer found but Resource not found\n");
			goto not_found;
		}

		coap_remove_observer(r, o);
	}

	net_pkt_unref(pkt);
	return;

not_found:
	r = coap_handle_request(&request, resources, options, opt_num);
	if (r < 0) {
		NET_ERR("No handler for such request (%d)\n", r);
	}

	net_pkt_unref(pkt);
}

static bool join_coap_multicast_group(void)
{
	static struct in6_addr my_addr = MY_IP6ADDR;
	static struct sockaddr_in6 mcast_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = ALL_NODES_LOCAL_COAP_MCAST,
		.sin6_port = htons(MY_COAP_PORT) };
	struct net_if_mcast_addr *mcast;
	struct net_if_addr *ifaddr;
	struct net_if *iface;

	iface = net_if_get_default();
	if (!iface) {
		NET_ERR("Could not get te default interface\n");
		return false;
	}

#if defined(CONFIG_NET_APP_SETTINGS)
	if (net_addr_pton(AF_INET6,
			  CONFIG_NET_APP_MY_IPV6_ADDR,
			  &my_addr) < 0) {
		NET_ERR("Invalid IPv6 address %s",
			CONFIG_NET_APP_MY_IPV6_ADDR);
	}
#endif

	ifaddr = net_if_ipv6_addr_add(iface, &my_addr, NET_ADDR_AUTOCONF, 0);
	if (!ifaddr) {
		NET_ERR("Could not add unicast address to interface");
		return false;
	}

	ifaddr->addr_state = NET_ADDR_PREFERRED;

	mcast = net_if_ipv6_maddr_add(iface, &mcast_addr.sin6_addr);
	if (!mcast) {
		NET_ERR("Could not add multicast address to interface\n");
		return false;
	}

	return true;
}

static void retransmit_request(struct k_work *work)
{
	struct coap_pending *pending;
	int r;

	pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return;
	}

	/* ref to avoid being freed by sendto() */
	net_pkt_ref(pending->pkt);

	r = net_context_sendto(pending->pkt, &pending->addr,
			       sizeof(struct sockaddr_in6),
			       NULL, 0, NULL, NULL);
	if (r < 0) {
		/* no error, keeps retry */
		net_pkt_unref(pending->pkt);
	}

	if (!coap_pending_cycle(pending)) {
		/* last retransmit, clear pending and unreference packet */
		coap_pending_clear(pending);
		return;
	}

	/* unref to balance ref made previously */
	net_pkt_unref(pending->pkt);
	k_delayed_work_submit(&retransmit_work, pending->timeout);
}

enum lidar_state {WAIT_FOR_MAGIC, READ_INDEX, READ_DATA};

static inline int lidar_read_statemachine(u8_t data_byte, u8_t *data)
{
	static u8_t *data_ptr;
	static u8_t actual_index;
	int state = WAIT_FOR_MAGIC;


	switch (state) {
		case WAIT_FOR_MAGIC:
			if(data_byte == 0xFA) {
				state = READ_INDEX;
				printk("READ_INDEX\n");
			}
		break;

		case READ_INDEX:
			if (data_byte == actual_index + 0xA0) {
				data_ptr = data;
				*data_ptr = actual_index;
				data_ptr ++;
				if (++actual_index == 90) {
					actual_index = 0;
				}
				state = READ_DATA;
				printk("READ_DATA\n");
			} else {
				actual_index = 0;
				state = WAIT_FOR_MAGIC;
			}
		break;

		case READ_DATA:
			*data_ptr = data_byte;
			data_ptr++;
			if(data_ptr == data+21) {
				state = WAIT_FOR_MAGIC;
				return 1;
			}
		break;
	}
	return 0;
}

static inline int sync_buffer(u8_t *data, u8_t *buffer, int length)
{
	u8_t *buffer_ptr;
	int ret = 0;

	for (buffer_ptr = buffer; length; length--, buffer_ptr++) {
		printk("got: %x\n", *buffer_ptr);
		ret |= lidar_read_statemachine(*buffer_ptr, data);
	}
	return ret;
}

void print_data(u8_t *data) {
	u8_t index = data[0];
	u16_t speed = data[1] | (data[2] << 8);
	u16_t dist_1 = data[3] | (data[4] << 8);
	u16_t dist_2 = data[7] | (data[8] << 8);
	u16_t dist_3 = data[11] | (data[12] << 8);
	u16_t dist_4 = data[15] | (data[16] << 8);
	printk("%d\n", dist_1);
	printk("%d\n", dist_2);
	printk("%d\n", dist_3);
	printk("%d\n", dist_4);
	(void) speed;
	(void) index;
}

void lidar_parse(struct device *port)
{
	static u8_t data[21];
	u8_t buffer[22];
	int num_bytes;
	
	do {
		num_bytes = uart_fifo_read(port, buffer, sizeof (buffer));
		printk("%d bytes\n", num_bytes);
		if (num_bytes && sync_buffer(data, buffer, num_bytes)) {
			print_data(data);
		}

	} while (num_bytes > 0);
}

void uart6_isr(struct device *port)
{

	if(uart_irq_rx_ready(port))
	{
		lidar_parse(port);
	}
}

void uart6_dma_callback(struct device *dev, u32_t channel, int error_code)
{
	printk("dma-callback\n");
}

void main(void)
{
	u64_t cycles_per_sec = 0;

	static struct sockaddr_in6 any_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = IN6ADDR_ANY_INIT,
		.sin6_port = htons(MY_COAP_PORT) };
	int r;

	pwm_dev = device_get_binding("PWM_RAIL");
	if (!pwm_dev) {
		printk("Could not get PWM device\n");
		return;
	}

	pwm_get_cycles_per_sec(pwm_dev, PWM_CHANNEL_RAIL1, &cycles_per_sec);
	pwm_period = cycles_per_sec/PWM_FREQ;
	pwm_pin_set_cycles(pwm_dev, PWM_CHANNEL_RAIL1, pwm_period, 0);

	gpio_dev = device_get_binding("GPIOB");
	if (!gpio_dev) {
		printk("Could not get GPIO device\n");
		return;
	}

	gpio_pin_configure(gpio_dev, FW_PIN, GPIO_DIR_OUT);
	gpio_pin_configure(gpio_dev, RW_PIN, GPIO_DIR_OUT);
	gpio_pin_write(gpio_dev, FW_PIN, 0);
	gpio_pin_write(gpio_dev, RW_PIN, 0);

	uart6_dev = device_get_binding("UART_6");
	if (!uart6_dev) {
		printk("Could not get UART6 device\n");
		return;
	}

	//uart_irq_callback_set(uart6_dev, uart6_isr);
	//uart_irq_rx_enable(uart6_dev);
	uart_dma_read(uart6_dev,uart_buffer, sizeof(uart_buffer), uart6_dma_callback);

	if (!join_coap_multicast_group()) {
		NET_ERR("Could not join CoAP multicast group\n");
		return;
	}

	r = net_context_get(PF_INET6, SOCK_DGRAM, IPPROTO_UDP, &context);
	if (r) {
		NET_ERR("Could not get an UDP context\n");
		return;
	}

	r = net_context_bind(context, (struct sockaddr *) &any_addr,
			     sizeof(any_addr));
	if (r) {
		NET_ERR("Could not bind the context\n");
		return;
	}

	k_delayed_work_init(&retransmit_work, retransmit_request);

	r = net_context_recv(context, udp_receive, 0, NULL);
	if (r) {
		NET_ERR("Could not receive in the context\n");
		return;
	}

	struct net_if *iface;
	iface = net_if_get_default();
	printk("IP: %s\n", net_sprint_ipv6_addr(net_if_ipv6_get_ll(iface, NET_ADDR_PREFERRED)));
}
