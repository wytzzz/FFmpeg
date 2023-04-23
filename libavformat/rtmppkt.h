/*
 * RTMP packet utilities
 * Copyright (c) 2009 Konstantin Shishkov
 *
 * This file is part of FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#ifndef AVFORMAT_RTMPPKT_H
#define AVFORMAT_RTMPPKT_H

#include "libavcodec/bytestream.h"
#include "avformat.h"
#include "url.h"

/** maximum possible number of different RTMP channels */
#define RTMP_CHANNELS 65599

/**
 * channels used to for RTMP packets with different purposes (i.e. data, network
 * control, remote procedure calls, etc.)
 */
 //在 RTMP 协议中，一个连接可以包含多个通道（channel），每个通道都是一个独立的双向数据传输通道，用于在连接上传输不同类型的数据。每个通道都有一个唯一的 ID，用于标识该通道。
 //通常情况下，一个 RTMP 连接至少包含两个通道，一个用于传输控制消息，另一个用于传输音视频数据。除此之外，RTMP 协议还定义了其他几种类型的通道，例如元数据通道、共享对象通道等

 //每个通道都有一个接收队列和一个发送队列，用于存储接收到和发送的数据包。在发送数据包时，需要指定数据包所属的通道 ID，以便接收方正确识别数据包。
 //同时，每个通道还有一个计数器，用于记录该通道接收和发送的字节数。

 //通过使用多个通道，RTMP 协议可以同时传输多种类型的数据，并且可以对每种类型的数据进行独立的控制和管理。
 //这样可以提高数据传输的效率和稳定性，使得 RTMP 协议在音视频流媒体传输领域得到了广泛应用。
 enum RTMPChannel {
    RTMP_NETWORK_CHANNEL = 2,   ///表示通道的唯一 ID，通常由 RTMP 对象自动分配 < channel for network-related messages (bandwidth report, ping, etc)
    RTMP_SYSTEM_CHANNEL,        ///表示该通道接收到的数据包队列< channel for sending server control messages
    RTMP_AUDIO_CHANNEL,         ///< channel for audio data
    RTMP_VIDEO_CHANNEL   = 6,   ///< channel for video data
    RTMP_SOURCE_CHANNEL  = 8,   ///< channel for a/v invokes
};

/**
 * known RTMP packet types
 */
 //rtmp数据包类型
typedef enum RTMPPacketType {
    RTMP_PT_CHUNK_SIZE   =  1,  ///数据包的分块大小 < chunk size change
    RTMP_PT_BYTES_READ   =  3,  ///表示已经读取的字节数。< number of bytes read
    RTMP_PT_USER_CONTROL,       ///用户控制消息< user control
    RTMP_PT_WINDOW_ACK_SIZE,    ///表示窗口确认大小< window acknowledgement size
    RTMP_PT_SET_PEER_BW,        ///表示设置对端带宽< peer bandwidth
    RTMP_PT_AUDIO        =  8,  ///音频数据包< audio packet
    RTMP_PT_VIDEO,              ///视频数据包< video packet
    RTMP_PT_FLEX_STREAM  = 15,  ///Flex共享流< Flex shared stream
    RTMP_PT_FLEX_OBJECT,        ///Flex共享对象< Flex shared object
    RTMP_PT_FLEX_MESSAGE,       ///Flex共享消息< Flex shared message
    RTMP_PT_NOTIFY,             ///某些通知信息< some notification
    RTMP_PT_SHARED_OBJ,         ///表示共享对象< shared object
    RTMP_PT_INVOKE,             ///表示调用某些流操作< invoke some stream action
    RTMP_PT_METADATA     = 22,  ///即表示 FLV 元数据。< FLV metadata
} RTMPPacketType;

/**
 * possible RTMP packet header sizes
 */
enum RTMPPacketSize {
    RTMP_PS_TWELVEBYTES = 0, ///< packet has 12-byte header
    RTMP_PS_EIGHTBYTES,      ///< packet has 8-byte header
    RTMP_PS_FOURBYTES,       ///< packet has 4-byte header
    RTMP_PS_ONEBYTE          ///< packet is really a next chunk of a packet
};

/**
 * structure for holding RTMP packets
 */
typedef struct RTMPPacket {
    int            channel_id; ///表示 RTMP 通道 ID，用于标识数据包所属的通道。< RTMP channel ID (nothing to do with audio/video channels though)
    RTMPPacketType type;       ///表示数据包的类型。RTMP 协议中定义了多种数据包类型，例如音视频数据包、元数据包、控制消息等< packet payload type
    uint32_t       timestamp;  ///表示数据包的时间戳，单位为毫秒。对于音视频数据包，时间戳表示该数据包的绝对时间戳< packet full timestamp
    uint32_t       ts_field;   ///表示时间戳或时间戳增量，单位为毫秒。< 24-bit timestamp or increment to the previous one, in milliseconds (latter only for media packets). Clipped to a maximum of 0xFFFFFF, indicating an extended timestamp field.
    uint32_t       extra;      ///表示附加信息，通常用于传输流数据时使用的额外通道 ID。< probably an additional channel ID used during streaming data
    uint8_t        *data;      ///表示数据包的有效载荷，即数据包的实际内容< packet payload
    int            size;       ///表示数据包的有效载荷大小< packet payload size
    int            offset;     ///表示已经读取的数据包有效载荷的字节数。< amount of data read so far
    int            read;       ///表示已经读取的数据包的总字节数，包括头部和有效载荷。< amount read, including headers
} RTMPPacket;

/**
 * Create new RTMP packet with given attributes.
 *
 * @param pkt        packet
 * @param channel_id packet channel ID
 * @param type       packet type
 * @param timestamp  packet timestamp
 * @param size       packet size
 * @return zero on success, negative value otherwise
 */
int ff_rtmp_packet_create(RTMPPacket *pkt, int channel_id, RTMPPacketType type,
                          int timestamp, int size);

/**
 * Free RTMP packet.
 *
 * @param pkt packet
 */
void ff_rtmp_packet_destroy(RTMPPacket *pkt);

/**
 * Read RTMP packet sent by the server.
 *
 * @param h          reader context
 * @param p          packet
 * @param chunk_size current chunk size
 * @param prev_pkt   previously read packet headers for all channels
 *                   (may be needed for restoring incomplete packet header)
 * @param nb_prev_pkt number of allocated elements in prev_pkt
 * @return number of bytes read on success, negative value otherwise
 */
int ff_rtmp_packet_read(URLContext *h, RTMPPacket *p,
                        int chunk_size, RTMPPacket **prev_pkt,
                        int *nb_prev_pkt);
/**
 * Read internal RTMP packet sent by the server.
 *
 * @param h          reader context
 * @param p          packet
 * @param chunk_size current chunk size
 * @param prev_pkt   previously read packet headers for all channels
 *                   (may be needed for restoring incomplete packet header)
 * @param nb_prev_pkt number of allocated elements in prev_pkt
 * @param c          the first byte already read
 * @return number of bytes read on success, negative value otherwise
 */
int ff_rtmp_packet_read_internal(URLContext *h, RTMPPacket *p, int chunk_size,
                                 RTMPPacket **prev_pkt, int *nb_prev_pkt,
                                 uint8_t c);

/**
 * Send RTMP packet to the server.
 *
 * @param h          reader context
 * @param p          packet to send
 * @param chunk_size current chunk size
 * @param prev_pkt   previously sent packet headers for all channels
 *                   (may be used for packet header compressing)
 * @param nb_prev_pkt number of allocated elements in prev_pkt
 * @return number of bytes written on success, negative value otherwise
 */
int ff_rtmp_packet_write(URLContext *h, RTMPPacket *p,
                         int chunk_size, RTMPPacket **prev_pkt,
                         int *nb_prev_pkt);

/**
 * Print information and contents of RTMP packet.
 *
 * @param ctx        output context
 * @param p          packet to dump
 */
void ff_rtmp_packet_dump(void *ctx, RTMPPacket *p);

/**
 * Enlarge the prev_pkt array to fit the given channel
 *
 * @param prev_pkt    array with previously sent packet headers
 * @param nb_prev_pkt number of allocated elements in prev_pkt
 * @param channel     the channel number that needs to be allocated
 */
int ff_rtmp_check_alloc_array(RTMPPacket **prev_pkt, int *nb_prev_pkt,
                              int channel);

/**
 * @name Functions used to work with the AMF format (which is also used in .flv)
 * @see amf_* funcs in libavformat/flvdec.c
 * @{
 */

/**
 * Calculate number of bytes taken by first AMF entry in data.
 *
 * @param data input data
 * @param data_end input buffer end
 * @return number of bytes used by first AMF entry
 */
int ff_amf_tag_size(const uint8_t *data, const uint8_t *data_end);

/**
 * Retrieve value of given AMF object field in string form.
 *
 * @param data     AMF object data
 * @param data_end input buffer end
 * @param name     name of field to retrieve
 * @param dst      buffer for storing result
 * @param dst_size output buffer size
 * @return 0 if search and retrieval succeeded, negative value otherwise
 */
int ff_amf_get_field_value(const uint8_t *data, const uint8_t *data_end,
                           const uint8_t *name, uint8_t *dst, int dst_size);

/**
 * Write boolean value in AMF format to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 * @param val value to write
 */
void ff_amf_write_bool(uint8_t **dst, int val);

/**
 * Write number in AMF format to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 * @param num value to write
 */
void ff_amf_write_number(uint8_t **dst, double num);

/**
 * Write string in AMF format to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 * @param str string to write
 */
void ff_amf_write_string(uint8_t **dst, const char *str);

/**
 * Write a string consisting of two parts in AMF format to a buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 * @param str1 first string to write, may be null
 * @param str2 second string to write, may be null
 */
void ff_amf_write_string2(uint8_t **dst, const char *str1, const char *str2);

/**
 * Write AMF NULL value to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 */
void ff_amf_write_null(uint8_t **dst);

/**
 * Write marker for AMF object to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 */
void ff_amf_write_object_start(uint8_t **dst);

/**
 * Write string used as field name in AMF object to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 * @param str string to write
 */
void ff_amf_write_field_name(uint8_t **dst, const char *str);

/**
 * Write marker for end of AMF object to buffer.
 *
 * @param dst pointer to the input buffer (will be modified)
 */
void ff_amf_write_object_end(uint8_t **dst);

/**
 * Read AMF boolean value.
 *
 *@param[in,out] gbc GetByteContext initialized with AMF-formatted data
 *@param[out]    val 0 or 1
 *@return 0 on success or an AVERROR code on failure
*/
int ff_amf_read_bool(GetByteContext *gbc, int *val);

/**
 * Read AMF number value.
 *
 *@param[in,out] gbc GetByteContext initialized with AMF-formatted data
 *@param[out]    val read value
 *@return 0 on success or an AVERROR code on failure
*/
int ff_amf_read_number(GetByteContext *gbc, double *val);

/**
 * Get AMF string value.
 *
 * This function behaves the same as ff_amf_read_string except that
 * it does not expect the AMF type prepended to the actual data.
 * Appends a trailing null byte to output string in order to
 * ease later parsing.
 *
 *@param[in,out] gbc     GetByteContext initialized with AMF-formatted data
 *@param[out]    str     read string
 *@param[in]     strsize buffer size available to store the read string
 *@param[out]    length  read string length
 *@return 0 on success or an AVERROR code on failure
*/
int ff_amf_get_string(GetByteContext *bc, uint8_t *str,
                      int strsize, int *length);

/**
 * Read AMF string value.
 *
 * Appends a trailing null byte to output string in order to
 * ease later parsing.
 *
 *@param[in,out] gbc     GetByteContext initialized with AMF-formatted data
 *@param[out]    str     read string
 *@param[in]     strsize buffer size available to store the read string
 *@param[out]    length  read string length
 *@return 0 on success or an AVERROR code on failure
*/
int ff_amf_read_string(GetByteContext *gbc, uint8_t *str,
                       int strsize, int *length);

/**
 * Read AMF NULL value.
 *
 *@param[in,out] gbc GetByteContext initialized with AMF-formatted data
 *@return 0 on success or an AVERROR code on failure
*/
int ff_amf_read_null(GetByteContext *gbc);

/**
 * Match AMF string with a NULL-terminated string.
 *
 * @return 0 if the strings do not match.
 */

int ff_amf_match_string(const uint8_t *data, int size, const char *str);

/** @} */ // AMF funcs

#endif /* AVFORMAT_RTMPPKT_H */
