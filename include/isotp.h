/*
 * Copyright (c) 2019 Alexander Wachter
 *
 * SPDX-License-Identifier: Apache-2.0
 */

/**
 * @file
 * @brief Public API for ISO-TP (ISO15765)
 *
 * ISO-TP is a transport protocol for CAN (Controller Area Network)
 */

#ifndef ZEPHYR_INCLUDE_ISOTP_H_
#define ZEPHYR_INCLUDE_ISOTP_H_

/**
 * @brief CAN ISO-TP Interface
 * @defgroup can_iso_tp CAN ISO-TP Interface
 * @ingroup CAN
 * @{
 */

#include <can.h>
#include <zephyr/types.h>
#include <net/buf.h>

/*
 * Abbreviations
 * BS      Block Size
 * CAN_DL  CAN LL data size
 * CF      Consecutive Frame
 * CTS     Continue to send
 * DLC     Data length code
 * FC      Flow Control
 * FF      First Frame
 * FS      Flow Status
 * AE      Adders Extension
 */

/**
 * N_Result according to ISO 15765-2:2016
 * ISO_TP_ prefix is used to be zephyr conform
 */
#define ISO_TP_N_OK              0  /**< Completed successfully */
#define ISO_TP_N_TIMEOUT_A      -1  /**< Ar/As has timed out */
#define ISO_TP_N_TIMEOUT_BS     -2  /**< Reception of next FC has timed out */
#define ISO_TP_N_TIMEOUT_CR     -3  /**< Cr has timed out */
#define ISO_TP_N_WRONG_SN       -4  /**< Unexpected sequence number */
#define ISO_TP_N_INVALID_FS     -5  /**< Invalid flow status received*/
#define ISO_TP_N_UNEXP_PDU      -6  /**< Unexpected PDU received */
#define ISO_TP_N_WFT_OVRN       -7  /**< Maximum number of WAIT flowStatus PDUs exceeded */
#define ISO_TP_N_BUFFER_OVERFLW -8  /**< FlowStatus OVFLW PDU was received */
#define ISO_TP_N_ERROR          -9  /**< General error */

/** Implementation specific errors*/
#define ISO_TP_NO_FREE_FILTER    -10 /**< Can't bind or send because the CAN device has no filter left*/
#define ISO_TP_NO_NET_BUF_LEFT   -11 /**< No net buffer left to allocate */
#define ISO_TP_NO_BUF_DATA_LEFT  -12 /**< Not sufficient space in the buffer left for the data */
#define ISO_TP_NO_CTX_LEFT       -13 /**< No context buffer left to allocate */
#define ISO_TP_RCV_TIMEOUT       -14 /**< Timeout for rcv */

#ifdef __cplusplus
extern "C" {
#endif

struct iso_tp_msg_id {
	union {
		u32_t std_id  : 11;
		u32_t ext_id  : 29;
	};
	u32_t id_type : 1;
	u32_t use_ext_addr : 1;
	u8_t ext_addr;
};
/*
 * STmin is split in two ranges:
 *   0-127: 0ms-127ms
 * 128-240: Reserved
 * 241-249: 100us-900us (multiples of 100us)
 * 250-   : Reserved
 */
struct iso_tp_fc_opts {
	u8_t bs;     /** Block size. Number of CF PDUs before next CF is sent */
	u8_t stmin;  /** Minimum separation time. Min time between frames */
};

typedef void (*isotp_tx_callback_t)(int error_nr, void *arg);

struct iso_tp_send_ctx;
struct iso_tp_rcv_ctx;

/**
 * @brief Bind an address to a receiving context.
 *
 * This function binds a RX and TX address combination to a RX context.
 * When data arrives on the specified address it is buffered and can the
 * be read by calling iso_tp_rcv.
 * When calling this routine, a filter is applied in the CAN device and the
 * context is initialized. The contest must be valid until calling unbind.
 *
 * @param ctx     Context to store the internal states.
 * @param can_dev The CAN device to be used for sending and receiving.
 * @param rx_addr Identifier for incoming data.
 * @param tx_addr Identifier for FC frames.
 * @param opts    Flow control options.
 * @param timeout Timeout for FF SF buffer allocation.
 *
 * @retval ISO_TP_N_OK on success,
 *         ISO_TP_NO_FREE_FILTER if CAN device has no filters left.
 */
int iso_tp_bind(struct iso_tp_rcv_ctx *ctx, struct device *can_dev,
		const struct iso_tp_msg_id *rx_addr,
		const struct iso_tp_msg_id *tx_addr,
		const struct iso_tp_fc_opts *opts,
		s32_t timeout);

/**
 * @brief Unbind a context from the interface
 *
 * This function removes the binding from iso_tp_bind.
 * When calling this routine the filter is detached from the CAN device and
 * if a transmission is ongoing, buffers are freed.
 * The context can be discarded safely after this.
 *
 * @param ctx     Context that should be unbound.
 */
void iso_tp_unbind(struct iso_tp_rcv_ctx *ctx);

/**
 * @brief Read out received data from fifo.
 *
 * This function blocking reads the data from the receive fifo of the context.
 * If an error occurs the function returns a negative number and leaves the
 * data buffer unchanged.
 *
 * @param ctx     Context that is already bound.
 * @param data    Pointer to a buffer where the data is copied to.
 * @param len     Size of the buffer.
 * @param timeout Timeout for incoming data.
 *
 * @retval ISO_TP_N_OK on success, ISO_TP_WAIT_TIMEOUT when "timeout" timed out
 * or any of ISO_TP_N_* on error
 */
int iso_tp_rcv(struct iso_tp_rcv_ctx *ctx, u8_t *data, size_t len, s32_t timeout);

/**
 * @brief Get the net buffer on data reception
 *
 * This function blocks until a netbuffer is filled with all data (blocks) or an
 * error occurs. The netbuffers are still referenced and must be freed with
 * net_buf_unref after the data is processed. If bs was zero, the data is in a
 * single net_buf. Otherwise the data is fragmented in chunks of bs.
 * The block size is given when binding.
 *
 * @param ctx     Context that is already bound.
 * @param buffer  Pointer where the net_buf pointer is written to.
 * @param timeout Timeout for incoming data.
 *
 * @retval Remaining data length for this transfer if bs > 0, 0 for bs = 0,
 * ISO_TP_WAIT_TIMEOUT when "timeout" timed out or any of ISO_TP_N_* on error
 */
int iso_tp_rcv_net(struct iso_tp_rcv_ctx *ctx, struct net_buf **buffer,
		   s32_t timeout);

/**
 * @brief Send data
 *
 * This function is used to send data to a peer that listens to tx_addr.
 * A internal workqueue is used to transfer the segmented data.
 * data and context must be valid until the transmission has finished.
 * If a complete_cb is given this function is none blocking and the callback
 * is called on completion with the return value as parameter.
 *
 * @param ctx         Context to store the internal states.
 * @param can_dev     The CAN device to be used for sending and receiving.
 * @param data        Data to be sent.
 * @param len         Length of the data to be sent.
 * @param rx_addr     Identifier for FC frames.
 * @param tx_addr     Identifier for outgoing frames the receiver listens on.
 * @param complete_cb Function called on completion or NULL.
 * @param cb_arg      Argument passed to the complete callback.
 *
 * @retval ISO_TP_N_OK on success or any of ISO_TP_N_* on error
 */
int iso_tp_send(struct iso_tp_send_ctx *ctx, struct device *can_dev,
		const u8_t *data, size_t len,
		const struct iso_tp_msg_id *tx_addr,
		const struct iso_tp_msg_id *rx_addr,
		isotp_tx_callback_t complete_cb, void *cb_arg);

#ifdef CONFIG_ISOTP_ENABLE_CONTEXT_BUFFERS
/**
 * @brief Send data with buffered context
 *
 * This function is similar to iso_tp_send but the context is automatically
 * allocated from an internal pool.
 *
 * @param can_dev     The CAN device to be used for sending and receiving.
 * @param data        Data to be sent.
 * @param len         Length of the data to be sent.
 * @param rx_addr     Identifier for FC frames.
 * @param tx_addr     Identifier for outgoing frames the receiver listens on.
 * @param complete_cb Function called on completion or NULL.
 * @param cb_arg      Argument passed to the complete callback.
 * @param timeout     Timeout for buffer allocation.
 *
 * @retval ISO_TP_N_OK on success or any of ISO_TP_N_* on error
 */
int iso_tp_send_ctx_buf(struct device *can_dev,
			const u8_t *data, size_t len,
			const struct iso_tp_msg_id *tx_addr,
			const struct iso_tp_msg_id *rx_addr,
			isotp_tx_callback_t complete_cb, void *cb_arg,
			s32_t timeout);

/**
 * @brief Send data with buffered context
 *
 * This function is similar to iso_tp_send_ctx_buf but the data is carried in
 * a net_buf. net_buf_unref is called on the net_buf when sending is completed.
 *
 * @param can_dev     The CAN device to be used for sending and receiving.
 * @param data        Data to be sent.
 * @param len         Length of the data to be sent.
 * @param rx_addr     Identifier for FC frames.
 * @param tx_addr     Identifier for outgoing frames the receiver listens on.
 * @param complete_cb Function called on completion or NULL.
 * @param cb_arg      Argument passed to the complete callback.
 * @param timeout     Timeout for buffer allocation.
 *
 * @retval ISO_TP_N_OK on success or any of ISO_TP_* on error
 */
int iso_tp_send_net_ctx_buf(struct device *can_dev,
			    struct net_buf *data,
			    const struct iso_tp_msg_id *tx_addr,
			    const struct iso_tp_msg_id *rx_addr,
			    isotp_tx_callback_t complete_cb, void *cb_arg,
			    s32_t timeout);

#endif /*CONFIG_ISOTP_ENABLE_CONTEXT_BUFFERS*/

#if defined(CONFIG_ISOTP_USE_TX_BUF) && \
    defined(CONFIG_ISOTP_ENABLE_CONTEXT_BUFFERS)
/**
 * @brief Send data with buffered context
 *
 * This function is similar to iso_tp_send but the context is automatically
 * allocated from an internal pool and the data to be send is buffered in an
 * internal net_buff.
 *
 * @param can_dev     The CAN device to be used for sending and receiving.
 * @param data        Data to be sent.
 * @param len         Length of the data to be sent.
 * @param rx_addr     Identifier for FC frames.
 * @param tx_addr     Identifier for outgoing frames the receiver listens on.
 * @param complete_cb Function called on completion or NULL.
 * @param cb_arg      Argument passed to the complete callback.
 * @param timeout     Timeout for buffer allocation.
 *
 * @retval ISO_TP_N_OK on success or any of ISO_TP_* on error
 */
int iso_tp_send_buf(struct device *can_dev,
		    const u8_t *data, size_t len,
		    const struct iso_tp_msg_id *tx_addr,
		    const struct iso_tp_msg_id *rx_addr,
		    isotp_tx_callback_t complete_cb, void *cb_arg,
		    s32_t timeout);
#endif

struct iso_tp_callback {
	isotp_tx_callback_t cb;
	void *arg;
};

struct iso_tp_send_ctx {
	int filter_id;
	struct device *can_dev;
	union {
		struct net_buf *buf;
		struct {
			const u8_t *data;
			size_t len;
		};
	};
	u32_t error_nr;
	u8_t wft;
	u8_t bs;
	struct iso_tp_fc_opts opts;
		u8_t sn : 4;
	u8_t is_net_buf  : 1;
	u8_t is_ctx_slab : 1;
	u8_t has_callback: 1;
	u8_t state;
	struct k_work work;
	struct k_timer timeout;
	union {
		struct iso_tp_callback fin_cb;
		struct k_sem fin_sem;
	};
	struct iso_tp_msg_id rx_addr;
	struct iso_tp_msg_id tx_addr;
};

struct iso_tp_rcv_ctx {
	int filter_id;
	struct device *can_dev;
	struct net_buf *buf;
	struct net_buf *act_frag;
	sys_snode_t alloc_node;
	u32_t length;
	int error_nr;
	struct iso_tp_fc_opts opts;
	u8_t state;
	u8_t bs;
	u8_t wft;
	u8_t sn_expected : 4;
	struct k_work work;
	struct k_timer timeout;
	struct k_fifo fifo;
	struct iso_tp_msg_id rx_addr;
	struct iso_tp_msg_id tx_addr;
};

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* ZEPHYR_INCLUDE_ISOTP_H_ */
