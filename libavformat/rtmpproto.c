/*
 * RTMP network protocol
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

/**
 * @file
 * RTMP protocol
 */

#include "libavcodec/bytestream.h"
#include "libavutil/avstring.h"
#include "libavutil/base64.h"
#include "libavutil/intfloat.h"
#include "libavutil/lfg.h"
#include "libavutil/md5.h"
#include "libavutil/opt.h"
#include "libavutil/random_seed.h"
#include "avformat.h"
#include "internal.h"

#include "network.h"

#include "flv.h"
#include "rtmp.h"
#include "rtmpcrypt.h"
#include "rtmppkt.h"
#include "url.h"

#if CONFIG_ZLIB
#include <zlib.h>
#endif

#define APP_MAX_LENGTH 1024
#define TCURL_MAX_LENGTH 1024
#define FLASHVER_MAX_LENGTH 64
#define RTMP_PKTDATA_DEFAULT_SIZE 4096
#define RTMP_HEADER 11

/** RTMP protocol handler state */
typedef enum {
    STATE_START,      ///表示客户端的初始状态，表示客户端尚未执行任何操作。< client has not done anything yet
    STATE_HANDSHAKED, ///表示客户端已成功执行握手操作，即建立了客户端与服务器之间的通信。< client has performed handshake
    STATE_FCPUBLISH,  ///表示客户端正在向服务器发布流用于输出。< client FCPublishing stream (for output)
    STATE_PLAYING,    ///表示客户端已开始从服务器接收多媒体数据。< client has started receiving multimedia data from server
    STATE_SEEKING,    ///表示客户端已启动搜索操作，以在多媒体流中移动到特定位置。当搜索操作完成时，状态将返回到STATE_PLAYING。< client has started the seek operation. Back on STATE_PLAYING when the time comes
    STATE_PUBLISHING, ///表示客户端正在向服务器发送多媒体数据以进行输出。< client has started sending multimedia data to server (for output)
    STATE_RECEIVING,  ///客户端已经收到一个发布命令（作为输入）。< received a publish command (for input)
    STATE_SENDING,    ///客户端已经收到一个播放命令（作为输出）。< received a play command (for output)
    STATE_STOPPED,    ///广播已经停止。< the broadcast has been stopped
} ClientState;

typedef struct TrackedMethod {
    char *name;
    int id;
} TrackedMethod;

/** protocol handler context */
typedef struct RTMPContext {
    const AVClass *class;

    URLContext*   stream;                     ///指向TCP流的指针，用于与RTMP服务器交互。 < TCP stream used in interactions with RTMP server
    RTMPPacket    *prev_pkt[2];               ///用于存储读取和发送RTMP数据包的历史记录 < packet history used when reading and sending packets ([0] for reading, [1] for writing)
    int           nb_prev_pkt[2];             ///存储历史记录中每个RTMP数据包的数量。< number of elements in prev_pkt
    int           in_chunk_size;              ///输入RTMP数据包所分割成的块的大小。< size of the chunks incoming RTMP packets are divided into
    int           out_chunk_size;             ///输出RTMP数据包所分割成的块的大小。< size of the chunks outgoing RTMP packets are divided into
    //在RTMP协议中，输入连接通常指客户端向服务器发送数据的连接，
    // 例如客户端向服务器发送视频或音频流的连接。而输出连接则是指服务器向客户端发送数据的连接，例如服务器向客户端发送视频或音频流的连接
    int           is_input;                   ///输入/输出标志，指示该结构体是用于输入还是输出RTMP数据包< input/output flag
    char          *playpath;                  ///流标识符，用于播放（可能带有“mp4:”前缀）。< stream identifier to play (with possible "mp4:" prefix)
    int           live;                       ///指示流是否为实时流或录制流< 0: recorded, -1: live, -2: both
    char          *app;                       ///应用程序名称。< name of application
    char          *conn;                      ///将任意的AMF数据追加到连接消息中。< append arbitrary AMF data to the Connect message
    ClientState   state;                      ///当前状态< current state
    int           stream_id;                  ///服务器为流分配的ID。< ID assigned by the server for the stream
    uint8_t*      flv_data;                   ///包含解复用器数据的缓冲区< buffer with data for demuxer
    int           flv_size;                   ///当前缓冲区的大小< current buffer size
    int           flv_off;                    ///从当前缓冲区读取的字节数< number of bytes read from current buffer
    int           flv_nb_packets;             ///发布的FLV包数量< number of flv packets published
    RTMPPacket    out_pkt;                    ///从FLV音视频或元数据创建的RTMP数据包（用于输出）。< rtmp packet, created from flv a/v or metadata (for output)
    uint32_t      receive_report_size;        ///当接收到的字节数达到此数值时，应向对等方报告接收到的字节数。< number of bytes after which we should report the number of received bytes to the peer
    uint64_t      bytes_read;                 ///从服务器读取的字节数。< number of bytes read from server
    uint64_t      last_bytes_read;            ///上次报告给服务器的读取字节数。< number of bytes read last reported to server
    uint32_t      last_timestamp;             ///上次收到的数据包中的时间戳。< last timestamp received in a packet
    int           skip_bytes;                 ///下一个写入调用中要从FLV流中跳过的字节数。< number of bytes to skip from the input FLV stream in the next write call
    int           has_audio;                  ///是否存在音频数据。< presence of audio data
    int           has_video;                  ///是否存在视频数据。< presence of video data
    int           received_metadata;          ///指示是否已接收有关流的元数据< Indicates if we have received metadata about the streams
    uint8_t       flv_header[RTMP_HEADER];    ///部分输入的FLV数据包头。< partial incoming flv packet header
    int           flv_header_bytes;           ///flv_header中初始化的字节数< number of initialized bytes in flv_header
    int           nb_invokes;                 ///跟踪调用消息的数量。< keeps track of invoke messages
    char*         tcurl;                      ///目标流的URL< url of the target stream
    char*         flashver;                   ///Flash插件版本。< version of the flash plugin
    char*         swfhash;                    ///解压后的SWF文件的SHA256哈希值（32字节）。< SHA256 hash of the decompressed SWF file (32 bytes)
    int           swfhash_len;                ///SHA256哈希值的长度< length of the SHA256 hash
    int           swfsize;                    ///解压后的SWF文件的大小< size of the decompressed SWF file
    char*         swfurl;                     ///SWF播放器的URL< url of the swf player
    char*         swfverify;                  ///播放器SWF文件的URL，可以自动计算哈希值/大小。< URL to player swf file, compute hash/size automatically
    char          swfverification[42];        ///SWF验证的哈希值< hash of the SWF verification
    char*         pageurl;                    ///订阅直播流的网页 URL< url of the web page
    char*         subscribe;                  ///要订阅的直播流名称< name of live stream to subscribe
    int           max_sent_unacked;           ///最大未确认发送字节数< max unacked sent bytes
    int           client_buffer_time;         ///客户端缓冲时间（以毫秒为单位）。< client buffer time in ms
    int           flush_interval;             ///< number of packets flushed in the same request (RTMPT only)
    int           encrypted;                  ///是否使用加密连接（仅在 RTMPE 中使用）。< use an encrypted connection (RTMPE only)
    TrackedMethod*tracked_methods;            ///< tracked methods buffer
    int           nb_tracked_methods;         ///< number of tracked methods
    int           tracked_methods_size;       ///< size of the tracked methods buffer
    int           listen;                     ///< listen mode flag
    int           listen_timeout;             ///< listen timeout to wait for new connections
    int           nb_streamid;                ///< The next stream id to return on createStream calls
    double        duration;                   ///由服务器返回的流的持续时间，以秒为单位（仅在非零时有效）。< Duration of the stream in seconds as returned by the server (only valid if non-zero)
    char          username[50];
    char          password[50];
    char          auth_params[500];
    int           do_reconnect;  //需要重连
    int           auth_tried;
} RTMPContext;

#define PLAYER_KEY_OPEN_PART_LEN 30   ///< length of partial key used for first client digest signing
/** Client key used for digest signing */
static const uint8_t rtmp_player_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'P', 'l', 'a', 'y', 'e', 'r', ' ', '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02,
    0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8,
    0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};

#define SERVER_KEY_OPEN_PART_LEN 36   ///< length of partial key used for first server digest signing
/** Key used for RTMP server digest signing */
static const uint8_t rtmp_server_key[] = {
    'G', 'e', 'n', 'u', 'i', 'n', 'e', ' ', 'A', 'd', 'o', 'b', 'e', ' ',
    'F', 'l', 'a', 's', 'h', ' ', 'M', 'e', 'd', 'i', 'a', ' ',
    'S', 'e', 'r', 'v', 'e', 'r', ' ', '0', '0', '1',

    0xF0, 0xEE, 0xC2, 0x4A, 0x80, 0x68, 0xBE, 0xE8, 0x2E, 0x00, 0xD0, 0xD1, 0x02,
    0x9E, 0x7E, 0x57, 0x6E, 0xEC, 0x5D, 0x2D, 0x29, 0x80, 0x6F, 0xAB, 0x93, 0xB8,
    0xE6, 0x36, 0xCF, 0xEB, 0x31, 0xAE
};

static int handle_chunk_size(URLContext *s, RTMPPacket *pkt);
static int handle_window_ack_size(URLContext *s, RTMPPacket *pkt);
static int handle_set_peer_bw(URLContext *s, RTMPPacket *pkt);

static int add_tracked_method(RTMPContext *rt, const char *name, int id)
{
    int err;

    if (rt->nb_tracked_methods + 1 > rt->tracked_methods_size) {
        rt->tracked_methods_size = (rt->nb_tracked_methods + 1) * 2;
        if ((err = av_reallocp_array(&rt->tracked_methods, rt->tracked_methods_size,
                               sizeof(*rt->tracked_methods))) < 0) {
            rt->nb_tracked_methods = 0;
            rt->tracked_methods_size = 0;
            return err;
        }
    }

    rt->tracked_methods[rt->nb_tracked_methods].name = av_strdup(name);
    if (!rt->tracked_methods[rt->nb_tracked_methods].name)
        return AVERROR(ENOMEM);
    rt->tracked_methods[rt->nb_tracked_methods].id = id;
    rt->nb_tracked_methods++;

    return 0;
}

static void del_tracked_method(RTMPContext *rt, int index)
{
    memmove(&rt->tracked_methods[index], &rt->tracked_methods[index + 1],
            sizeof(*rt->tracked_methods) * (rt->nb_tracked_methods - index - 1));
    rt->nb_tracked_methods--;
}

//该函数通常在RTMP协议中的命令消息中使用，用于匹配响应消息的事务ID和请求消息中的事务ID，以确保响应消息与请求消息匹配。
static int find_tracked_method(URLContext *s, RTMPPacket *pkt, int offset,
                               char **tracked_method)
{
    RTMPContext *rt = s->priv_data;
    GetByteContext gbc;
    double pkt_id;
    int ret;
    int i;

    bytestream2_init(&gbc, pkt->data + offset, pkt->size - offset);
    //读取事物id
    if ((ret = ff_amf_read_number(&gbc, &pkt_id)) < 0)
        return ret;

    //是否有匹配的id?
    for (i = 0; i < rt->nb_tracked_methods; i++) {
        if (rt->tracked_methods[i].id != pkt_id)
            continue;
        //返回方法名称
        *tracked_method = rt->tracked_methods[i].name;
        del_tracked_method(rt, i);
        break;
    }

    return 0;
}

static void free_tracked_methods(RTMPContext *rt)
{
    int i;

    for (i = 0; i < rt->nb_tracked_methods; i ++)
        av_freep(&rt->tracked_methods[i].name);
    av_freep(&rt->tracked_methods);
    rt->tracked_methods_size = 0;
    rt->nb_tracked_methods   = 0;
}

static int rtmp_send_packet(RTMPContext *rt, RTMPPacket *pkt, int track)
{
    int ret;

    //在发送数据包之前，代码会先判断数据包的类型是否为RTMP_PT_INVOKE，并且是否需要进行跟踪（即track参数是否为真）。
    // 如果需要进行跟踪，则代码会从RTMPPacket中解析出方法名和方法ID，并将其添加到RTMPContext的tracked_methods数组中。
    if (pkt->type == RTMP_PT_INVOKE && track) {
        GetByteContext gbc;
        char name[128];
        double pkt_id;
        int len;

        bytestream2_init(&gbc, pkt->data, pkt->size);
        if ((ret = ff_amf_read_string(&gbc, name, sizeof(name), &len)) < 0)
            goto fail;

        if ((ret = ff_amf_read_number(&gbc, &pkt_id)) < 0)
            goto fail;

        if ((ret = add_tracked_method(rt, name, pkt_id)) < 0)
            goto fail;
    }

    //将RTMPPacket中的数据按照RTMP协议格式封装成一个或多个RTMP Chunk，并通过RTMP协议发送到服务器。
    ret = ff_rtmp_packet_write(rt->stream, pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
fail:
    ff_rtmp_packet_destroy(pkt);
    return ret;
}

static int rtmp_write_amf_data(URLContext *s, char *param, uint8_t **p)
{
    char *field, *value;
    char type;

    /* The type must be B for Boolean, N for number, S for string, O for
     * object, or Z for null. For Booleans the data must be either 0 or 1 for
     * FALSE or TRUE, respectively. Likewise for Objects the data must be
     * 0 or 1 to end or begin an object, respectively. Data items in subobjects
     * may be named, by prefixing the type with 'N' and specifying the name
     * before the value (ie. NB:myFlag:1). This option may be used multiple times
     * to construct arbitrary AMF sequences. */
    if (param[0] && param[1] == ':') {
        type = param[0];
        value = param + 2;
    } else if (param[0] == 'N' && param[1] && param[2] == ':') {
        type = param[1];
        field = param + 3;
        value = strchr(field, ':');
        if (!value)
            goto fail;
        *value = '\0';
        value++;

        ff_amf_write_field_name(p, field);
    } else {
        goto fail;
    }

    switch (type) {
    case 'B':
        ff_amf_write_bool(p, value[0] != '0');
        break;
    case 'S':
        ff_amf_write_string(p, value);
        break;
    case 'N':
        ff_amf_write_number(p, strtod(value, NULL));
        break;
    case 'Z':
        ff_amf_write_null(p);
        break;
    case 'O':
        if (value[0] != '0')
            ff_amf_write_object_start(p);
        else
            ff_amf_write_object_end(p);
        break;
    default:
        goto fail;
        break;
    }

    return 0;

fail:
    av_log(s, AV_LOG_ERROR, "Invalid AMF parameter: %s\n", param);
    return AVERROR(EINVAL);
}

/**
 * Generate 'connect' call and send it to the server.
 */
static int gen_connect(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 4096 + APP_MAX_LENGTH)) < 0)
        return ret;

    p = pkt.data;

    //connect
    ff_amf_write_string(&p, "connect");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_object_start(&p);
    ff_amf_write_field_name(&p, "app");
    ff_amf_write_string2(&p, rt->app, rt->auth_params);

    if (!rt->is_input) {
        ff_amf_write_field_name(&p, "type");
        ff_amf_write_string(&p, "nonprivate");
    }
    ff_amf_write_field_name(&p, "flashVer");
    ff_amf_write_string(&p, rt->flashver);

    if (rt->swfurl || rt->swfverify) {
        ff_amf_write_field_name(&p, "swfUrl");
        if (rt->swfurl)
            ff_amf_write_string(&p, rt->swfurl);
        else
            ff_amf_write_string(&p, rt->swfverify);
    }

    ff_amf_write_field_name(&p, "tcUrl");
    ff_amf_write_string2(&p, rt->tcurl, rt->auth_params);

    //首先，如果RTMPContext中的is_input为真，则表示当前连接是输入连接，即客户端向服务器发送数据的连接。
    //接下来，代码会向输出缓冲区写入一些字段和值，这些字段和值表示客户端支持的一些功能和编解码器。
    //具体来说，代码会向输出缓冲区写入以下字段和值：
    //"fpad"字段：表示客户端是否支持填充。
    //"capabilities"字段：表示客户端支持的功能。这个值设置为15.0表示客户端支持所有功能。
    //"audioCodecs"字段：表示客户端支持的音频编解码器。这个值设置为4071.0表示客户端支持除了SUPPORT_SND_INTEL（0x0008）和SUPPORT_SND_UNUSED（0x0010）之外的所有音频编解码器。
    //"videoCodecs"字段：表示客户端支持的视频编解码器。这个值设置为252.0表示客户端支持所有视频编解码器。
    //"videoFunction"字段：表示客户端支持的视频功能。这个值设置为1.0表示客户端支持视频播放功能。
    //"pageUrl"字段：表示客户端当前所在的页面URL。如果RTMPContext中的pageurl不为空，则会将其写入输出缓冲区中。
    //总之，这段代码的作用是向RTMP服务器传递一些客户端支持的功能和编解码器信息，以便服务器在后续数据交换过程中正确地处理数据。
    if (rt->is_input) {
        ff_amf_write_field_name(&p, "fpad");
        ff_amf_write_bool(&p, 0);
        ff_amf_write_field_name(&p, "capabilities");
        ff_amf_write_number(&p, 15.0);

        /* Tell the server we support all the audio codecs except
         * SUPPORT_SND_INTEL (0x0008) and SUPPORT_SND_UNUSED (0x0010)
         * which are unused in the RTMP protocol implementation. */
        ff_amf_write_field_name(&p, "audioCodecs");
        ff_amf_write_number(&p, 4071.0);
        ff_amf_write_field_name(&p, "videoCodecs");
        ff_amf_write_number(&p, 252.0);
        ff_amf_write_field_name(&p, "videoFunction");
        ff_amf_write_number(&p, 1.0);

        if (rt->pageurl) {
            ff_amf_write_field_name(&p, "pageUrl");
            ff_amf_write_string(&p, rt->pageurl);
        }
    }
    ff_amf_write_object_end(&p);

    if (rt->conn) {
        char *param = rt->conn;

        // Write arbitrary AMF data to the Connect message.
        while (param) {
            char *sep;
            param += strspn(param, " ");
            if (!*param)
                break;
            sep = strchr(param, ' ');
            if (sep)
                *sep = '\0';
            if ((ret = rtmp_write_amf_data(s, param, &p)) < 0) {
                // Invalid AMF parameter.
                ff_rtmp_packet_destroy(&pkt);
                return ret;
            }

            if (sep)
                param = sep + 1;
            else
                break;
        }
    }

    pkt.size = p - pkt.data;

    //发送packet
    return rtmp_send_packet(rt, &pkt, 1);
}


#define RTMP_CTRL_ABORT_MESSAGE  (2)

static int read_connect(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt = { 0 };
    uint8_t *p;
    const uint8_t *cp;
    int ret;
    char command[64];
    int stringlen;
    double seqnum;
    uint8_t tmpstr[256];
    GetByteContext gbc;

    // handle RTMP Protocol Control Messages
    for (;;) {
        if ((ret = ff_rtmp_packet_read(rt->stream, &pkt, rt->in_chunk_size,
                                       &rt->prev_pkt[0], &rt->nb_prev_pkt[0])) < 0)
            return ret;
#ifdef DEBUG
        ff_rtmp_packet_dump(s, &pkt);
#endif
        if (pkt.type == RTMP_PT_CHUNK_SIZE) {
            if ((ret = handle_chunk_size(s, &pkt)) < 0) {
                ff_rtmp_packet_destroy(&pkt);
                return ret;
            }
        } else if (pkt.type == RTMP_CTRL_ABORT_MESSAGE) {
            av_log(s, AV_LOG_ERROR, "received abort message\n");
            ff_rtmp_packet_destroy(&pkt);
            return AVERROR_UNKNOWN;
        } else if (pkt.type == RTMP_PT_BYTES_READ) {
            av_log(s, AV_LOG_TRACE, "received acknowledgement\n");
        } else if (pkt.type == RTMP_PT_WINDOW_ACK_SIZE) {
            if ((ret = handle_window_ack_size(s, &pkt)) < 0) {
                ff_rtmp_packet_destroy(&pkt);
                return ret;
            }
        } else if (pkt.type == RTMP_PT_SET_PEER_BW) {
            if ((ret = handle_set_peer_bw(s, &pkt)) < 0) {
                ff_rtmp_packet_destroy(&pkt);
                return ret;
            }
        } else if (pkt.type == RTMP_PT_INVOKE) {
            // received RTMP Command Message
            break;
        } else {
            av_log(s, AV_LOG_ERROR, "Unknown control message type (%d)\n", pkt.type);
        }
        ff_rtmp_packet_destroy(&pkt);
    }

    cp = pkt.data;
    bytestream2_init(&gbc, cp, pkt.size);
    if (ff_amf_read_string(&gbc, command, sizeof(command), &stringlen)) {
        av_log(s, AV_LOG_ERROR, "Unable to read command string\n");
        ff_rtmp_packet_destroy(&pkt);
        return AVERROR_INVALIDDATA;
    }
    //connect
    if (strcmp(command, "connect")) {
        av_log(s, AV_LOG_ERROR, "Expecting connect, got %s\n", command);
        ff_rtmp_packet_destroy(&pkt);
        return AVERROR_INVALIDDATA;
    }
    ret = ff_amf_read_number(&gbc, &seqnum);
    if (ret)
        av_log(s, AV_LOG_WARNING, "SeqNum not found\n");
    /* Here one could parse an AMF Object with data as flashVers and others. */
    ret = ff_amf_get_field_value(gbc.buffer,
                                 gbc.buffer + bytestream2_get_bytes_left(&gbc),
                                 "app", tmpstr, sizeof(tmpstr));
    if (ret)
        av_log(s, AV_LOG_WARNING, "App field not found in connect\n");
    if (!ret && strcmp(tmpstr, rt->app))
        av_log(s, AV_LOG_WARNING, "App field don't match up: %s <-> %s\n",
               tmpstr, rt->app);
    ff_rtmp_packet_destroy(&pkt);

    // Send Window Acknowledgement Size (as defined in specification)
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL,
                                     RTMP_PT_WINDOW_ACK_SIZE, 0, 4)) < 0)
        return ret;
    p = pkt.data;
    // Inform the peer about how often we want acknowledgements about what
    // we send. (We don't check for the acknowledgements currently.)
    bytestream_put_be32(&p, rt->max_sent_unacked);
    pkt.size = p - pkt.data;
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);
    if (ret < 0)
        return ret;
    // Set Peer Bandwidth
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL,
                                     RTMP_PT_SET_PEER_BW, 0, 5)) < 0)
        return ret;
    p = pkt.data;
    // Tell the peer to only send this many bytes unless it gets acknowledgements.
    // This could be any arbitrary value we want here.
    bytestream_put_be32(&p, rt->max_sent_unacked);
    bytestream_put_byte(&p, 2); // dynamic
    pkt.size = p - pkt.data;
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);
    if (ret < 0)
        return ret;

    // User control
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL,
                                     RTMP_PT_USER_CONTROL, 0, 6)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be16(&p, 0); // 0 -> Stream Begin
    bytestream_put_be32(&p, 0); // Stream 0
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);
    if (ret < 0)
        return ret;

    // Chunk size
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL,
                                     RTMP_PT_CHUNK_SIZE, 0, 4)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be32(&p, rt->out_chunk_size);
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);
    if (ret < 0)
        return ret;

    // Send _result NetConnection.Connect.Success to connect
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL,
                                     RTMP_PT_INVOKE, 0,
                                     RTMP_PKTDATA_DEFAULT_SIZE)) < 0)
        return ret;

    //connect response
    p = pkt.data;
    ff_amf_write_string(&p, "_result");
    ff_amf_write_number(&p, seqnum);

    ff_amf_write_object_start(&p);
    ff_amf_write_field_name(&p, "fmsVer");
    ff_amf_write_string(&p, "FMS/3,0,1,123");
    ff_amf_write_field_name(&p, "capabilities");
    ff_amf_write_number(&p, 31);
    ff_amf_write_object_end(&p);

    ff_amf_write_object_start(&p);
    ff_amf_write_field_name(&p, "level");
    ff_amf_write_string(&p, "status");
    ff_amf_write_field_name(&p, "code");
    ff_amf_write_string(&p, "NetConnection.Connect.Success");
    ff_amf_write_field_name(&p, "description");
    ff_amf_write_string(&p, "Connection succeeded.");
    ff_amf_write_field_name(&p, "objectEncoding");
    ff_amf_write_number(&p, 0);
    ff_amf_write_object_end(&p);

    pkt.size = p - pkt.data;
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);
    if (ret < 0)
        return ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL,
                                     RTMP_PT_INVOKE, 0, 30)) < 0)
        return ret;
    p = pkt.data;
    ff_amf_write_string(&p, "onBWDone");
    ff_amf_write_number(&p, 0);
    ff_amf_write_null(&p);
    ff_amf_write_number(&p, 8192);
    pkt.size = p - pkt.data;
    ret = ff_rtmp_packet_write(rt->stream, &pkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&pkt);

    return ret;
}

/**
 * Generate 'releaseStream' call and send it to the server. It should make
 * the server release some channel for media streams.
 */
static int gen_release_stream(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 29 + strlen(rt->playpath))) < 0)
        return ret;

    av_log(s, AV_LOG_DEBUG, "Releasing stream...\n");
    p = pkt.data;
    ff_amf_write_string(&p, "releaseStream");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate 'FCPublish' call and send it to the server. It should make
 * the server prepare for receiving media streams.
 */
static int gen_fcpublish_stream(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 25 + strlen(rt->playpath))) < 0)
        return ret;

    av_log(s, AV_LOG_DEBUG, "FCPublish stream...\n");
    p = pkt.data;
    ff_amf_write_string(&p, "FCPublish");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate 'FCUnpublish' call and send it to the server. It should make
 * the server destroy stream.
 */
static int gen_fcunpublish_stream(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 27 + strlen(rt->playpath))) < 0)
        return ret;

    av_log(s, AV_LOG_DEBUG, "UnPublishing stream...\n");
    p = pkt.data;
    ff_amf_write_string(&p, "FCUnpublish");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate 'createStream' call and send it to the server. It should make
 * the server allocate some channel for media streams.
 */
static int gen_create_stream(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Creating stream...\n");

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 25)) < 0)
        return ret;

    p = pkt.data;
    ff_amf_write_string(&p, "createStream");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);

    return rtmp_send_packet(rt, &pkt, 1);
}


/**
 * Generate 'deleteStream' call and send it to the server. It should make
 * the server remove some channel for media streams.
 */
static int gen_delete_stream(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Deleting stream...\n");

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 34)) < 0)
        return ret;

    p = pkt.data;
    ff_amf_write_string(&p, "deleteStream");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_number(&p, rt->stream_id);

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate 'getStreamLength' call and send it to the server. If the server
 * knows the duration of the selected stream, it will reply with the duration
 * in seconds.
 */
static int gen_get_stream_length(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SOURCE_CHANNEL, RTMP_PT_INVOKE,
                                     0, 31 + strlen(rt->playpath))) < 0)
        return ret;

    p = pkt.data;
    ff_amf_write_string(&p, "getStreamLength");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate client buffer time and send it to the server.
 */
static int gen_buffer_time(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL, RTMP_PT_USER_CONTROL,
                                     1, 10)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be16(&p, 3); // SetBuffer Length
    bytestream_put_be32(&p, rt->stream_id);
    bytestream_put_be32(&p, rt->client_buffer_time);

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate 'play' call and send it to the server, then ping the server
 * to start actual playing.
 */
static int gen_play(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Sending play command for '%s'\n", rt->playpath);

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SOURCE_CHANNEL, RTMP_PT_INVOKE,
                                     0, 29 + strlen(rt->playpath))) < 0)
        return ret;

    pkt.extra = rt->stream_id;

    p = pkt.data;
    ff_amf_write_string(&p, "play");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);
    ff_amf_write_number(&p, rt->live * 1000);

    return rtmp_send_packet(rt, &pkt, 1);
}

static int gen_seek(URLContext *s, RTMPContext *rt, int64_t timestamp)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Sending seek command for timestamp %"PRId64"\n",
           timestamp);

    if ((ret = ff_rtmp_packet_create(&pkt, 3, RTMP_PT_INVOKE, 0, 26)) < 0)
        return ret;

    pkt.extra = rt->stream_id;

    p = pkt.data;
    ff_amf_write_string(&p, "seek");
    ff_amf_write_number(&p, 0); //no tracking back responses
    ff_amf_write_null(&p); //as usual, the first null param
    ff_amf_write_number(&p, timestamp); //where we want to jump

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate a pause packet that either pauses or unpauses the current stream.
 */
static int gen_pause(URLContext *s, RTMPContext *rt, int pause, uint32_t timestamp)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Sending pause command for timestamp %d\n",
           timestamp);

    if ((ret = ff_rtmp_packet_create(&pkt, 3, RTMP_PT_INVOKE, 0, 29)) < 0)
        return ret;

    pkt.extra = rt->stream_id;

    p = pkt.data;
    ff_amf_write_string(&p, "pause");
    ff_amf_write_number(&p, 0); //no tracking back responses
    ff_amf_write_null(&p); //as usual, the first null param
    ff_amf_write_bool(&p, pause); // pause or unpause
    ff_amf_write_number(&p, timestamp); //where we pause the stream

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate 'publish' call and send it to the server.
 */
static int gen_publish(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Sending publish command for '%s'\n", rt->playpath);

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SOURCE_CHANNEL, RTMP_PT_INVOKE,
                                     0, 30 + strlen(rt->playpath))) < 0)
        return ret;

    pkt.extra = rt->stream_id;

    p = pkt.data;
    ff_amf_write_string(&p, "publish");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, rt->playpath);
    ff_amf_write_string(&p, "live");

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate ping reply and send it to the server.
 */
static int gen_pong(URLContext *s, RTMPContext *rt, RTMPPacket *ppkt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if (ppkt->size < 6) {
        av_log(s, AV_LOG_ERROR, "Too short ping packet (%d)\n",
               ppkt->size);
        return AVERROR_INVALIDDATA;
    }

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL,RTMP_PT_USER_CONTROL,
                                     ppkt->timestamp + 1, 6)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be16(&p, 7); // PingResponse
    bytestream_put_be32(&p, AV_RB32(ppkt->data+2));

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate SWF verification message and send it to the server.
 */
static int gen_swf_verification(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    av_log(s, AV_LOG_DEBUG, "Sending SWF verification...\n");
    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL, RTMP_PT_USER_CONTROL,
                                     0, 44)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be16(&p, 27);
    memcpy(p, rt->swfverification, 42);

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate window acknowledgement size message and send it to the server.
 */
static int gen_window_ack_size(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL, RTMP_PT_WINDOW_ACK_SIZE,
                                     0, 4)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be32(&p, rt->max_sent_unacked);

    return rtmp_send_packet(rt, &pkt, 0);
}

/**
 * Generate check bandwidth message and send it to the server.
 */
static int gen_check_bw(URLContext *s, RTMPContext *rt)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 21)) < 0)
        return ret;

    p = pkt.data;
    ff_amf_write_string(&p, "_checkbw");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Generate report on bytes read so far and send it to the server.
 */
static int gen_bytes_read(URLContext *s, RTMPContext *rt, uint32_t ts)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_NETWORK_CHANNEL, RTMP_PT_BYTES_READ,
                                     ts, 4)) < 0)
        return ret;

    p = pkt.data;
    bytestream_put_be32(&p, rt->bytes_read);

    return rtmp_send_packet(rt, &pkt, 0);
}

static int gen_fcsubscribe_stream(URLContext *s, RTMPContext *rt,
                                  const char *subscribe)
{
    RTMPPacket pkt;
    uint8_t *p;
    int ret;

    if ((ret = ff_rtmp_packet_create(&pkt, RTMP_SYSTEM_CHANNEL, RTMP_PT_INVOKE,
                                     0, 27 + strlen(subscribe))) < 0)
        return ret;

    p = pkt.data;
    ff_amf_write_string(&p, "FCSubscribe");
    ff_amf_write_number(&p, ++rt->nb_invokes);
    ff_amf_write_null(&p);
    ff_amf_write_string(&p, subscribe);

    return rtmp_send_packet(rt, &pkt, 1);
}

/**
 * Put HMAC-SHA2 digest of packet data (except for the bytes where this digest
 * will be stored) into that packet.
 *
 * @param buf handshake data (1536 bytes)
 * @param encrypted use an encrypted connection (RTMPE)
 * @return offset to the digest inside input data
 */
static int rtmp_handshake_imprint_with_digest(uint8_t *buf, int encrypted)
{
    int ret, digest_pos;

    //计算digest的pos
    //第一个参数表示需要计算的缓冲区，第二个参数表示缓冲区的总长度，
    // 第三个参数表示摘要数据的位置偏移量，第四个参数表示摘要数据的长度。
    // 根据这些参数，函数会计算出摘要数据需要插入的位置，并将其返回
    if (encrypted)
        digest_pos = ff_rtmp_calc_digest_pos(buf, 772, 728, 776);
    else
        digest_pos = ff_rtmp_calc_digest_pos(buf, 8, 728, 12);

    //该函数的作用是对输入的数据进行SHA256哈希计算，并将计算结果存储在指定位置，以便后续的数据包可以使用这个摘要数据进行验证
    ret = ff_rtmp_calc_digest(buf, RTMP_HANDSHAKE_PACKET_SIZE, digest_pos,
                              rtmp_player_key, PLAYER_KEY_OPEN_PART_LEN,
                              buf + digest_pos);
    if (ret < 0)
        return ret;

    return digest_pos;
}

/**
 * Verify that the received server response has the expected digest value.
 *
 * @param buf handshake data received from the server (1536 bytes)
 * @param off position to search digest offset from
 * @return 0 if digest is valid, digest position otherwise
 */
static int rtmp_validate_digest(uint8_t *buf, int off)
{
    uint8_t digest[32];
    int ret, digest_pos;

    digest_pos = ff_rtmp_calc_digest_pos(buf, off, 728, off + 4);

    ret = ff_rtmp_calc_digest(buf, RTMP_HANDSHAKE_PACKET_SIZE, digest_pos,
                              rtmp_server_key, SERVER_KEY_OPEN_PART_LEN,
                              digest);
    if (ret < 0)
        return ret;

    if (!memcmp(digest, buf + digest_pos, 32))
        return digest_pos;
    return 0;
}

static int rtmp_calc_swf_verification(URLContext *s, RTMPContext *rt,
                                      uint8_t *buf)
{
    uint8_t *p;
    int ret;

    if (rt->swfhash_len != 32) {
        av_log(s, AV_LOG_ERROR,
               "Hash of the decompressed SWF file is not 32 bytes long.\n");
        return AVERROR(EINVAL);
    }

    p = &rt->swfverification[0];
    bytestream_put_byte(&p, 1);
    bytestream_put_byte(&p, 1);
    bytestream_put_be32(&p, rt->swfsize);
    bytestream_put_be32(&p, rt->swfsize);

    if ((ret = ff_rtmp_calc_digest(rt->swfhash, 32, 0, buf, 32, p)) < 0)
        return ret;

    return 0;
}

#if CONFIG_ZLIB
static int rtmp_uncompress_swfplayer(uint8_t *in_data, int64_t in_size,
                                     uint8_t **out_data, int64_t *out_size)
{
    z_stream zs = { 0 };
    void *ptr;
    int size;
    int ret = 0;

    zs.avail_in = in_size;
    zs.next_in  = in_data;
    ret = inflateInit(&zs);
    if (ret != Z_OK)
        return AVERROR_UNKNOWN;

    do {
        uint8_t tmp_buf[16384];

        zs.avail_out = sizeof(tmp_buf);
        zs.next_out  = tmp_buf;

        ret = inflate(&zs, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            ret = AVERROR_UNKNOWN;
            goto fail;
        }

        size = sizeof(tmp_buf) - zs.avail_out;
        if (!(ptr = av_realloc(*out_data, *out_size + size))) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        *out_data = ptr;

        memcpy(*out_data + *out_size, tmp_buf, size);
        *out_size += size;
    } while (zs.avail_out == 0);

fail:
    inflateEnd(&zs);
    return ret;
}
#endif

static int rtmp_calc_swfhash(URLContext *s)
{
    RTMPContext *rt = s->priv_data;
    uint8_t *in_data = NULL, *out_data = NULL, *swfdata;
    int64_t in_size;
    URLContext *stream = NULL;
    char swfhash[32];
    int swfsize;
    int ret = 0;

    /* Get the SWF player file. */
    if ((ret = ffurl_open_whitelist(&stream, rt->swfverify, AVIO_FLAG_READ,
                                    &s->interrupt_callback, NULL,
                                    s->protocol_whitelist, s->protocol_blacklist, s)) < 0) {
        av_log(s, AV_LOG_ERROR, "Cannot open connection %s.\n", rt->swfverify);
        goto fail;
    }

    if ((in_size = ffurl_seek(stream, 0, AVSEEK_SIZE)) < 0) {
        ret = AVERROR(EIO);
        goto fail;
    }

    if (!(in_data = av_malloc(in_size))) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    if ((ret = ffurl_read_complete(stream, in_data, in_size)) < 0)
        goto fail;

    if (in_size < 3) {
        ret = AVERROR_INVALIDDATA;
        goto fail;
    }

    if (!memcmp(in_data, "CWS", 3)) {
#if CONFIG_ZLIB
        int64_t out_size;
        /* Decompress the SWF player file using Zlib. */
        if (!(out_data = av_malloc(8))) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        *in_data = 'F'; // magic stuff
        memcpy(out_data, in_data, 8);
        out_size = 8;

        if ((ret = rtmp_uncompress_swfplayer(in_data + 8, in_size - 8,
                                             &out_data, &out_size)) < 0)
            goto fail;
        swfsize = out_size;
        swfdata = out_data;
#else
        av_log(s, AV_LOG_ERROR,
               "Zlib is required for decompressing the SWF player file.\n");
        ret = AVERROR(EINVAL);
        goto fail;
#endif
    } else {
        swfsize = in_size;
        swfdata = in_data;
    }

    /* Compute the SHA256 hash of the SWF player file. */
    if ((ret = ff_rtmp_calc_digest(swfdata, swfsize, 0,
                                   "Genuine Adobe Flash Player 001", 30,
                                   swfhash)) < 0)
        goto fail;

    /* Set SWFVerification parameters. */
    av_opt_set_bin(rt, "rtmp_swfhash", swfhash, 32, 0);
    rt->swfsize = swfsize;

fail:
    av_freep(&in_data);
    av_freep(&out_data);
    ffurl_close(stream);
    return ret;
}

/**
 * Perform handshake with the server by means of exchanging pseudorandom data
 * signed with HMAC-SHA2 digest.
 *
 * @return 0 if handshake succeeds, negative value otherwise
 */
static int rtmp_handshake(URLContext *s, RTMPContext *rt)
{
    AVLFG rnd;
    //对的，FFmpeg 在实现 RTMP 协议时，将客户端的 C0 和 C1 消息打包在同一个数据包中发送给服务器。
    // 具体来说，FFmpeg 会先将 C0 的版本号和 C1 的时间戳打包成一个 5 字节的二进制数据，
    // 然后再将 C1 的随机数据拼接在后面，组成一个 157 字节的二进制数据包，最后将这个数据包发送给服务器。
    uint8_t tosend    [RTMP_HANDSHAKE_PACKET_SIZE+1] = {
        3,                // unencrypted data
        0, 0, 0, 0,       // client uptime
        RTMP_CLIENT_VER1,
        RTMP_CLIENT_VER2,
        RTMP_CLIENT_VER3,
        RTMP_CLIENT_VER4,
    };
    uint8_t clientdata[RTMP_HANDSHAKE_PACKET_SIZE];
    uint8_t serverdata[RTMP_HANDSHAKE_PACKET_SIZE+1];
    int i;
    int server_pos, client_pos;
    uint8_t digest[32], signature[32];
    int ret, type = 0;

    av_log(s, AV_LOG_DEBUG, "Handshaking...\n");


    //生成随机数字
    av_lfg_init(&rnd, 0xDEADC0DE);
    // generate handshake packet - 1536 bytes of pseudorandom data
    for (i = 9; i <= RTMP_HANDSHAKE_PACKET_SIZE; i++)
        tosend[i] = av_lfg_get(&rnd) >> 24;

    if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
        /* When the client wants to use RTMPE, we have to change the command
         * byte to 0x06 which means to use encrypted data and we have to set
         * the flash version to at least 9.0.115.0. */
        tosend[0] = 6;
        tosend[5] = 128;
        tosend[6] = 0;
        tosend[7] = 3;
        tosend[8] = 2;

        /* Initialize the Diffie-Hellmann context and generate the public key
         * to send to the server. */

       // 调用rtmp_handshake_imprint_with_digest函数对握手请求进行修改，以便计算出用于验证握手响应的摘要。
        if ((ret = ff_rtmpe_gen_pub_key(rt->stream, tosend + 1)) < 0)
            return ret;
    }

    //将摘要信息也放入handshake数据包中
    client_pos = rtmp_handshake_imprint_with_digest(tosend + 1, rt->encrypted);
    if (client_pos < 0)
        return client_pos;

    //调用ffurl_write函数将握手请求发送给服务端。
    if ((ret = ffurl_write(rt->stream, tosend,
                           RTMP_HANDSHAKE_PACKET_SIZE + 1)) < 0) {
        av_log(s, AV_LOG_ERROR, "Cannot write RTMP handshake request\n");
        return ret;
    }

    //调用ffurl_read_complete函数从流中读取服务端的s0/s1，并将其存储在serverdata数组中。
    if ((ret = ffurl_read_complete(rt->stream, serverdata,
                                   RTMP_HANDSHAKE_PACKET_SIZE + 1)) < 0) {
        av_log(s, AV_LOG_ERROR, "Cannot read RTMP handshake response\n");
        return ret;
    }

    //再次调用ffurl_read_complete函数从流中读取服务端发送的s2，并将其存储在clientdata数组中。
    if ((ret = ffurl_read_complete(rt->stream, clientdata,
                                   RTMP_HANDSHAKE_PACKET_SIZE)) < 0) {
        av_log(s, AV_LOG_ERROR, "Cannot read RTMP handshake response\n");
        return ret;
    }

    //打印出服务端响应的类型和版本号信息。
    av_log(s, AV_LOG_DEBUG, "Type answer %d\n", serverdata[0]);
    av_log(s, AV_LOG_DEBUG, "Server version %d.%d.%d.%d\n",
           serverdata[5], serverdata[6], serverdata[7], serverdata[8]);

    if (rt->is_input && serverdata[5] >= 3) {
        //判断握手数据是否有效，如果无效则返回错误。
        server_pos = rtmp_validate_digest(serverdata + 1, 772);
        if (server_pos < 0)
            return server_pos;

        if (!server_pos) {
            type = 1;
            server_pos = rtmp_validate_digest(serverdata + 1, 8);
            if (server_pos < 0)
                return server_pos;

            if (!server_pos) {
                av_log(s, AV_LOG_ERROR, "Server response validating failed\n");
                return AVERROR(EIO);
            }
        }

        /* Generate SWFVerification token (SHA256 HMAC hash of decompressed SWF,
         * key are the last 32 bytes of the server handshake. */
        if (rt->swfsize) {
            if ((ret = rtmp_calc_swf_verification(s, rt, serverdata + 1 +
                                                  RTMP_HANDSHAKE_PACKET_SIZE - 32)) < 0)
                return ret;
        }

        ret = ff_rtmp_calc_digest(tosend + 1 + client_pos, 32, 0,
                                  rtmp_server_key, sizeof(rtmp_server_key),
                                  digest);
        if (ret < 0)
            return ret;

        ret = ff_rtmp_calc_digest(clientdata, RTMP_HANDSHAKE_PACKET_SIZE - 32,
                                  0, digest, 32, signature);
        if (ret < 0)
            return ret;

        if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
            /* Compute the shared secret key sent by the server and initialize
             * the RC4 encryption. */
            if ((ret = ff_rtmpe_compute_secret_key(rt->stream, serverdata + 1,
                                                   tosend + 1, type)) < 0)
                return ret;

            /* Encrypt the signature received by the server. */
            ff_rtmpe_encrypt_sig(rt->stream, signature, digest, serverdata[0]);
        }

        if (memcmp(signature, clientdata + RTMP_HANDSHAKE_PACKET_SIZE - 32, 32)) {
            av_log(s, AV_LOG_ERROR, "Signature mismatch\n");
            return AVERROR(EIO);
        }

        for (i = 0; i < RTMP_HANDSHAKE_PACKET_SIZE; i++)
            tosend[i] = av_lfg_get(&rnd) >> 24;
        ret = ff_rtmp_calc_digest(serverdata + 1 + server_pos, 32, 0,
                                  rtmp_player_key, sizeof(rtmp_player_key),
                                  digest);
        if (ret < 0)
            return ret;

        ret = ff_rtmp_calc_digest(tosend, RTMP_HANDSHAKE_PACKET_SIZE - 32, 0,
                                  digest, 32,
                                  tosend + RTMP_HANDSHAKE_PACKET_SIZE - 32);
        if (ret < 0)
            return ret;

        if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
            /* Encrypt the signature to be send to the server. */
            ff_rtmpe_encrypt_sig(rt->stream, tosend +
                                 RTMP_HANDSHAKE_PACKET_SIZE - 32, digest,
                                 serverdata[0]);
        }

        // write reply back to the server
        if ((ret = ffurl_write(rt->stream, tosend,
                               RTMP_HANDSHAKE_PACKET_SIZE)) < 0)
            return ret;

        if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
            /* Set RC4 keys for encryption and update the keystreams. */
            if ((ret = ff_rtmpe_update_keystream(rt->stream)) < 0)
                return ret;
        }
    } else {
        if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
            /* Compute the shared secret key sent by the server and initialize
             * the RC4 encryption. */
            if ((ret = ff_rtmpe_compute_secret_key(rt->stream, serverdata + 1,
                            tosend + 1, 1)) < 0)
                return ret;

            if (serverdata[0] == 9) {
                /* Encrypt the signature received by the server. */
                ff_rtmpe_encrypt_sig(rt->stream, signature, digest,
                                     serverdata[0]);
            }
        }

        if ((ret = ffurl_write(rt->stream, serverdata + 1,
                               RTMP_HANDSHAKE_PACKET_SIZE)) < 0)
            return ret;

        if (CONFIG_FFRTMPCRYPT_PROTOCOL && rt->encrypted) {
            /* Set RC4 keys for encryption and update the keystreams. */
            if ((ret = ff_rtmpe_update_keystream(rt->stream)) < 0)
                return ret;
        }
    }

    return 0;
}

static int rtmp_receive_hs_packet(RTMPContext* rt, uint32_t *first_int,
                                  uint32_t *second_int, char *arraydata,
                                  int size)
{
    int inoutsize;

    inoutsize = ffurl_read_complete(rt->stream, arraydata,
                                    RTMP_HANDSHAKE_PACKET_SIZE);
    if (inoutsize <= 0)
        return AVERROR(EIO);
    if (inoutsize != RTMP_HANDSHAKE_PACKET_SIZE) {
        av_log(rt, AV_LOG_ERROR, "Erroneous Message size %d"
               " not following standard\n", (int)inoutsize);
        return AVERROR(EINVAL);
    }

    *first_int  = AV_RB32(arraydata);
    *second_int = AV_RB32(arraydata + 4);
    return 0;
}

static int rtmp_send_hs_packet(RTMPContext* rt, uint32_t first_int,
                               uint32_t second_int, char *arraydata, int size)
{
    int inoutsize;

    AV_WB32(arraydata, first_int);
    AV_WB32(arraydata + 4, second_int);
    inoutsize = ffurl_write(rt->stream, arraydata,
                            RTMP_HANDSHAKE_PACKET_SIZE);
    if (inoutsize != RTMP_HANDSHAKE_PACKET_SIZE) {
        av_log(rt, AV_LOG_ERROR, "Unable to write answer\n");
        return AVERROR(EIO);
    }

    return 0;
}

/**
 * rtmp handshake server side
 */
static int rtmp_server_handshake(URLContext *s, RTMPContext *rt)
{
    uint8_t buffer[RTMP_HANDSHAKE_PACKET_SIZE];
    uint32_t hs_epoch;
    uint32_t hs_my_epoch;
    uint8_t hs_c1[RTMP_HANDSHAKE_PACKET_SIZE];
    uint8_t hs_s1[RTMP_HANDSHAKE_PACKET_SIZE];
    uint32_t zeroes;
    uint32_t temp       = 0;
    int randomidx       = 0;
    int inoutsize       = 0;
    int ret;

    inoutsize = ffurl_read_complete(rt->stream, buffer, 1);       // Receive C0
    if (inoutsize <= 0) {
        av_log(s, AV_LOG_ERROR, "Unable to read handshake\n");
        return AVERROR(EIO);
    }
    // Check Version
    if (buffer[0] != 3) {
        av_log(s, AV_LOG_ERROR, "RTMP protocol version mismatch\n");
        return AVERROR(EIO);
    }
    if (ffurl_write(rt->stream, buffer, 1) <= 0) {                 // Send S0
        av_log(s, AV_LOG_ERROR,
               "Unable to write answer - RTMP S0\n");
        return AVERROR(EIO);
    }
    /* Receive C1 */
    ret = rtmp_receive_hs_packet(rt, &hs_epoch, &zeroes, hs_c1,
                                 RTMP_HANDSHAKE_PACKET_SIZE);
    if (ret) {
        av_log(s, AV_LOG_ERROR, "RTMP Handshake C1 Error\n");
        return ret;
    }
    /* Send S1 */
    /* By now same epoch will be sent */
    hs_my_epoch = hs_epoch;
    /* Generate random */
    for (randomidx = 8; randomidx < (RTMP_HANDSHAKE_PACKET_SIZE);
         randomidx += 4)
        AV_WB32(hs_s1 + randomidx, av_get_random_seed());

    ret = rtmp_send_hs_packet(rt, hs_my_epoch, 0, hs_s1,
                              RTMP_HANDSHAKE_PACKET_SIZE);
    if (ret) {
        av_log(s, AV_LOG_ERROR, "RTMP Handshake S1 Error\n");
        return ret;
    }
    /* Send S2 */
    ret = rtmp_send_hs_packet(rt, hs_epoch, 0, hs_c1,
                              RTMP_HANDSHAKE_PACKET_SIZE);
    if (ret) {
        av_log(s, AV_LOG_ERROR, "RTMP Handshake S2 Error\n");
        return ret;
    }
    /* Receive C2 */
    ret = rtmp_receive_hs_packet(rt, &temp, &zeroes, buffer,
                                 RTMP_HANDSHAKE_PACKET_SIZE);
    if (ret) {
        av_log(s, AV_LOG_ERROR, "RTMP Handshake C2 Error\n");
        return ret;
    }
    if (temp != hs_my_epoch)
        av_log(s, AV_LOG_WARNING,
               "Erroneous C2 Message epoch does not match up with C1 epoch\n");
    if (memcmp(buffer + 8, hs_s1 + 8,
               RTMP_HANDSHAKE_PACKET_SIZE - 8))
        av_log(s, AV_LOG_WARNING,
               "Erroneous C2 Message random does not match up\n");

    return 0;
}

static int handle_chunk_size(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    int ret;

    if (pkt->size < 4) {
        av_log(s, AV_LOG_ERROR,
               "Too short chunk size change packet (%d)\n",
               pkt->size);
        return AVERROR_INVALIDDATA;
    }

    if (!rt->is_input) {
        /* Send the same chunk size change packet back to the server,
         * setting the outgoing chunk size to the same as the incoming one. */
        if ((ret = ff_rtmp_packet_write(rt->stream, pkt, rt->out_chunk_size,
                                        &rt->prev_pkt[1], &rt->nb_prev_pkt[1])) < 0)
            return ret;
        rt->out_chunk_size = AV_RB32(pkt->data);
    }
    //设置chunk_size
    rt->in_chunk_size = AV_RB32(pkt->data);
    if (rt->in_chunk_size <= 0) {
        av_log(s, AV_LOG_ERROR, "Incorrect chunk size %d\n",
               rt->in_chunk_size);
        return AVERROR_INVALIDDATA;
    }
    av_log(s, AV_LOG_DEBUG, "New incoming chunk size = %d\n",
           rt->in_chunk_size);

    return 0;
}

static int handle_user_control(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    int t, ret;

    if (pkt->size < 2) {
        av_log(s, AV_LOG_ERROR, "Too short user control packet (%d)\n",
               pkt->size);
        return AVERROR_INVALIDDATA;
    }

    //解析自类型
    t = AV_RB16(pkt->data);
    if (t == 6) { // PingRequest
        if ((ret = gen_pong(s, rt, pkt)) < 0)
            return ret;
    } else if (t == 26) {
        if (rt->swfsize) {
            if ((ret = gen_swf_verification(s, rt)) < 0)
                return ret;
        } else {
            av_log(s, AV_LOG_WARNING, "Ignoring SWFVerification request.\n");
        }
    }

    return 0;
}

static int handle_set_peer_bw(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;

    if (pkt->size < 4) {
        av_log(s, AV_LOG_ERROR,
               "Peer bandwidth packet is less than 4 bytes long (%d)\n",
               pkt->size);
        return AVERROR_INVALIDDATA;
    }

    // We currently don't check how much the peer has acknowledged of
    // what we have sent. To do that properly, we should call
    // gen_window_ack_size here, to tell the peer that we want an
    // acknowledgement with (at least) that interval.
    rt->max_sent_unacked = AV_RB32(pkt->data);
    if (rt->max_sent_unacked <= 0) {
        av_log(s, AV_LOG_ERROR, "Incorrect set peer bandwidth %d\n",
               rt->max_sent_unacked);
        return AVERROR_INVALIDDATA;

    }
    av_log(s, AV_LOG_DEBUG, "Max sent, unacked = %d\n", rt->max_sent_unacked);

    return 0;
}

static int handle_window_ack_size(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;

    if (pkt->size < 4) {
        av_log(s, AV_LOG_ERROR,
               "Too short window acknowledgement size packet (%d)\n",
               pkt->size);
        return AVERROR_INVALIDDATA;
    }

    rt->receive_report_size = AV_RB32(pkt->data);
    if (rt->receive_report_size <= 0) {
        av_log(s, AV_LOG_ERROR, "Incorrect window acknowledgement size %d\n",
               rt->receive_report_size);
        return AVERROR_INVALIDDATA;
    }
    av_log(s, AV_LOG_DEBUG, "Window acknowledgement size = %d\n", rt->receive_report_size);
    // Send an Acknowledgement packet after receiving half the maximum
    // size, to make sure the peer can keep on sending without waiting
    // for acknowledgements.
    rt->receive_report_size >>= 1;

    return 0;
}

static int do_adobe_auth(RTMPContext *rt, const char *user, const char *salt,
                         const char *opaque, const char *challenge)
{
    uint8_t hash[16];
    char hashstr[AV_BASE64_SIZE(sizeof(hash))], challenge2[10];
    struct AVMD5 *md5 = av_md5_alloc();
    if (!md5)
        return AVERROR(ENOMEM);

    snprintf(challenge2, sizeof(challenge2), "%08x", av_get_random_seed());

    av_md5_init(md5);
    av_md5_update(md5, user, strlen(user));
    av_md5_update(md5, salt, strlen(salt));
    av_md5_update(md5, rt->password, strlen(rt->password));
    av_md5_final(md5, hash);
    av_base64_encode(hashstr, sizeof(hashstr), hash,
                     sizeof(hash));
    av_md5_init(md5);
    av_md5_update(md5, hashstr, strlen(hashstr));
    if (opaque)
        av_md5_update(md5, opaque, strlen(opaque));
    else if (challenge)
        av_md5_update(md5, challenge, strlen(challenge));
    av_md5_update(md5, challenge2, strlen(challenge2));
    av_md5_final(md5, hash);
    av_base64_encode(hashstr, sizeof(hashstr), hash,
                     sizeof(hash));
    snprintf(rt->auth_params, sizeof(rt->auth_params),
             "?authmod=%s&user=%s&challenge=%s&response=%s",
             "adobe", user, challenge2, hashstr);
    if (opaque)
        av_strlcatf(rt->auth_params, sizeof(rt->auth_params),
                    "&opaque=%s", opaque);

    av_free(md5);
    return 0;
}

static int do_llnw_auth(RTMPContext *rt, const char *user, const char *nonce)
{
    uint8_t hash[16];
    char hashstr1[33], hashstr2[33];
    const char *realm = "live";
    const char *method = "publish";
    const char *qop = "auth";
    const char *nc = "00000001";
    char cnonce[10];
    struct AVMD5 *md5 = av_md5_alloc();
    if (!md5)
        return AVERROR(ENOMEM);

    snprintf(cnonce, sizeof(cnonce), "%08x", av_get_random_seed());

    av_md5_init(md5);
    av_md5_update(md5, user, strlen(user));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, realm, strlen(realm));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, rt->password, strlen(rt->password));
    av_md5_final(md5, hash);
    ff_data_to_hex(hashstr1, hash, 16, 1);
    hashstr1[32] = '\0';

    av_md5_init(md5);
    av_md5_update(md5, method, strlen(method));
    av_md5_update(md5, ":/", 2);
    av_md5_update(md5, rt->app, strlen(rt->app));
    if (!strchr(rt->app, '/'))
        av_md5_update(md5, "/_definst_", strlen("/_definst_"));
    av_md5_final(md5, hash);
    ff_data_to_hex(hashstr2, hash, 16, 1);
    hashstr2[32] = '\0';

    av_md5_init(md5);
    av_md5_update(md5, hashstr1, strlen(hashstr1));
    av_md5_update(md5, ":", 1);
    if (nonce)
        av_md5_update(md5, nonce, strlen(nonce));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, nc, strlen(nc));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, cnonce, strlen(cnonce));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, qop, strlen(qop));
    av_md5_update(md5, ":", 1);
    av_md5_update(md5, hashstr2, strlen(hashstr2));
    av_md5_final(md5, hash);
    ff_data_to_hex(hashstr1, hash, 16, 1);

    snprintf(rt->auth_params, sizeof(rt->auth_params),
             "?authmod=%s&user=%s&nonce=%s&cnonce=%s&nc=%s&response=%s",
             "llnw", user, nonce, cnonce, nc, hashstr1);

    av_free(md5);
    return 0;
}

static int handle_connect_error(URLContext *s, const char *desc)
{
    RTMPContext *rt = s->priv_data;
    char buf[300], *ptr, authmod[15];
    int i = 0, ret = 0;
    const char *user = "", *salt = "", *opaque = NULL,
               *challenge = NULL, *cptr = NULL, *nonce = NULL;

    if (!(cptr = strstr(desc, "authmod=adobe")) &&
        !(cptr = strstr(desc, "authmod=llnw"))) {
        av_log(s, AV_LOG_ERROR,
               "Unknown connect error (unsupported authentication method?)\n");
        return AVERROR_UNKNOWN;
    }
    cptr += strlen("authmod=");
    while (*cptr && *cptr != ' ' && i < sizeof(authmod) - 1)
        authmod[i++] = *cptr++;
    authmod[i] = '\0';

    if (!rt->username[0] || !rt->password[0]) {
        av_log(s, AV_LOG_ERROR, "No credentials set\n");
        return AVERROR_UNKNOWN;
    }

    if (strstr(desc, "?reason=authfailed")) {
        av_log(s, AV_LOG_ERROR, "Incorrect username/password\n");
        return AVERROR_UNKNOWN;
    } else if (strstr(desc, "?reason=nosuchuser")) {
        av_log(s, AV_LOG_ERROR, "Incorrect username\n");
        return AVERROR_UNKNOWN;
    }

    if (rt->auth_tried) {
        av_log(s, AV_LOG_ERROR, "Authentication failed\n");
        return AVERROR_UNKNOWN;
    }

    rt->auth_params[0] = '\0';

    if (strstr(desc, "code=403 need auth")) {
        snprintf(rt->auth_params, sizeof(rt->auth_params),
                 "?authmod=%s&user=%s", authmod, rt->username);
        return 0;
    }

    if (!(cptr = strstr(desc, "?reason=needauth"))) {
        av_log(s, AV_LOG_ERROR, "No auth parameters found\n");
        return AVERROR_UNKNOWN;
    }

    av_strlcpy(buf, cptr + 1, sizeof(buf));
    ptr = buf;

    while (ptr) {
        char *next  = strchr(ptr, '&');
        char *value = strchr(ptr, '=');
        if (next)
            *next++ = '\0';
        if (value) {
            *value++ = '\0';
            if (!strcmp(ptr, "user")) {
                user = value;
            } else if (!strcmp(ptr, "salt")) {
                salt = value;
            } else if (!strcmp(ptr, "opaque")) {
                opaque = value;
            } else if (!strcmp(ptr, "challenge")) {
                challenge = value;
            } else if (!strcmp(ptr, "nonce")) {
                nonce = value;
            } else {
                av_log(s, AV_LOG_INFO, "Ignoring unsupported var %s\n", ptr);
            }
        } else {
            av_log(s, AV_LOG_WARNING, "Variable %s has NULL value\n", ptr);
        }
        ptr = next;
    }

    if (!strcmp(authmod, "adobe")) {
        if ((ret = do_adobe_auth(rt, user, salt, opaque, challenge)) < 0)
            return ret;
    } else {
        if ((ret = do_llnw_auth(rt, user, nonce)) < 0)
            return ret;
    }

    rt->auth_tried = 1;
    return 0;
}

static int handle_invoke_error(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    const uint8_t *data_end = pkt->data + pkt->size;
    char *tracked_method = NULL;
    int level = AV_LOG_ERROR;
    uint8_t tmpstr[256];
    int ret;

    if ((ret = find_tracked_method(s, pkt, 9, &tracked_method)) < 0)
        return ret;

    if (!ff_amf_get_field_value(pkt->data + 9, data_end,
                                "description", tmpstr, sizeof(tmpstr))) {
        if (tracked_method && (!strcmp(tracked_method, "_checkbw")      ||
                               !strcmp(tracked_method, "releaseStream") ||
                               !strcmp(tracked_method, "FCSubscribe")   ||
                               !strcmp(tracked_method, "FCPublish"))) {
            /* Gracefully ignore Adobe-specific historical artifact errors. */
            level = AV_LOG_WARNING;
            ret = 0;
        } else if (tracked_method && !strcmp(tracked_method, "getStreamLength")) {
            level = rt->live ? AV_LOG_DEBUG : AV_LOG_WARNING;
            ret = 0;
        } else if (tracked_method && !strcmp(tracked_method, "connect")) {
            ret = handle_connect_error(s, tmpstr);
            if (!ret) {
                rt->do_reconnect = 1;
                level = AV_LOG_VERBOSE;
            }
        } else
            ret = AVERROR_UNKNOWN;
        av_log(s, level, "Server error: %s\n", tmpstr);
    }

    av_free(tracked_method);
    return ret;
}

static int write_begin(URLContext *s)
{
    RTMPContext *rt = s->priv_data;
    PutByteContext pbc;
    RTMPPacket spkt = { 0 };
    int ret;

    // Send Stream Begin 1
    if ((ret = ff_rtmp_packet_create(&spkt, RTMP_NETWORK_CHANNEL,
                                     RTMP_PT_USER_CONTROL, 0, 6)) < 0) {
        av_log(s, AV_LOG_ERROR, "Unable to create response packet\n");
        return ret;
    }

    bytestream2_init_writer(&pbc, spkt.data, spkt.size);
    bytestream2_put_be16(&pbc, 0);          // 0 -> Stream Begin
    bytestream2_put_be32(&pbc, rt->nb_streamid);

    ret = ff_rtmp_packet_write(rt->stream, &spkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);

    ff_rtmp_packet_destroy(&spkt);

    return ret;
}

static int write_status(URLContext *s, RTMPPacket *pkt,
                        const char *status, const char *filename)
{
    RTMPContext *rt = s->priv_data;
    RTMPPacket spkt = { 0 };
    char statusmsg[128];
    uint8_t *pp;
    int ret;

    if ((ret = ff_rtmp_packet_create(&spkt, RTMP_SYSTEM_CHANNEL,
                                     RTMP_PT_INVOKE, 0,
                                     RTMP_PKTDATA_DEFAULT_SIZE)) < 0) {
        av_log(s, AV_LOG_ERROR, "Unable to create response packet\n");
        return ret;
    }

    pp = spkt.data;
    spkt.extra = pkt->extra;
    ff_amf_write_string(&pp, "onStatus");
    ff_amf_write_number(&pp, 0);
    ff_amf_write_null(&pp);

    ff_amf_write_object_start(&pp);
    ff_amf_write_field_name(&pp, "level");
    ff_amf_write_string(&pp, "status");
    ff_amf_write_field_name(&pp, "code");
    ff_amf_write_string(&pp, status);
    ff_amf_write_field_name(&pp, "description");
    snprintf(statusmsg, sizeof(statusmsg),
             "%s is now published", filename);
    ff_amf_write_string(&pp, statusmsg);
    ff_amf_write_field_name(&pp, "details");
    ff_amf_write_string(&pp, filename);
    ff_amf_write_object_end(&pp);

    spkt.size = pp - spkt.data;
    ret = ff_rtmp_packet_write(rt->stream, &spkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&spkt);

    return ret;
}

static int send_invoke_response(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    double seqnum;
    char filename[128];
    char command[64];
    int stringlen;
    char *pchar;
    const uint8_t *p = pkt->data;
    uint8_t *pp      = NULL;
    RTMPPacket spkt  = { 0 };
    GetByteContext gbc;
    int ret;

    bytestream2_init(&gbc, p, pkt->size);
    if (ff_amf_read_string(&gbc, command, sizeof(command),
                           &stringlen)) {
        av_log(s, AV_LOG_ERROR, "Error in PT_INVOKE\n");
        return AVERROR_INVALIDDATA;
    }

    ret = ff_amf_read_number(&gbc, &seqnum);
    if (ret)
        return ret;
    ret = ff_amf_read_null(&gbc);
    if (ret)
        return ret;
    if (!strcmp(command, "FCPublish") ||
        !strcmp(command, "publish")) {
        ret = ff_amf_read_string(&gbc, filename,
                                 sizeof(filename), &stringlen);
        if (ret) {
            if (ret == AVERROR(EINVAL))
                av_log(s, AV_LOG_ERROR, "Unable to parse stream name - name too long?\n");
            else
                av_log(s, AV_LOG_ERROR, "Unable to parse stream name\n");
            return ret;
        }
        // check with url
        if (s->filename) {
            pchar = strrchr(s->filename, '/');
            if (!pchar) {
                av_log(s, AV_LOG_WARNING,
                       "Unable to find / in url %s, bad format\n",
                       s->filename);
                pchar = s->filename;
            }
            pchar++;
            if (strcmp(pchar, filename))
                av_log(s, AV_LOG_WARNING, "Unexpected stream %s, expecting"
                       " %s\n", filename, pchar);
        }
        //切换状态,表示成功收到publish.
        rt->state = STATE_RECEIVING;
    }

    //推流命令
    if (!strcmp(command, "FCPublish")) {
        if ((ret = ff_rtmp_packet_create(&spkt, RTMP_SYSTEM_CHANNEL,
                                         RTMP_PT_INVOKE, 0,
                                         RTMP_PKTDATA_DEFAULT_SIZE)) < 0) {
            av_log(s, AV_LOG_ERROR, "Unable to create response packet\n");
            return ret;
        }
        pp = spkt.data;
        ff_amf_write_string(&pp, "onFCPublish");
    } else if (!strcmp(command, "publish")) {
        ret = write_begin(s);
        if (ret < 0)
            return ret;

        // Send onStatus(NetStream.Publish.Start)
        return write_status(s, pkt, "NetStream.Publish.Start",
                           filename);
    //拉流命令
    } else if (!strcmp(command, "play")) {
        ret = write_begin(s);
        if (ret < 0)
            return ret;
        rt->state = STATE_SENDING;
        return write_status(s, pkt, "NetStream.Play.Start",
                            filename);
    //其他命令
    } else {
        if ((ret = ff_rtmp_packet_create(&spkt, RTMP_SYSTEM_CHANNEL,
                                         RTMP_PT_INVOKE, 0,
                                         RTMP_PKTDATA_DEFAULT_SIZE)) < 0) {
            av_log(s, AV_LOG_ERROR, "Unable to create response packet\n");
            return ret;
        }
        pp = spkt.data;
        ff_amf_write_string(&pp, "_result");
        ff_amf_write_number(&pp, seqnum);
        ff_amf_write_null(&pp);
        //createStream
        //对于"createStream"命令，函数会将RTMPContext中的nb_streamid增加1，并将其写入响应消息中。这个值用于标识流媒体中的流ID，并在需要时创建新的流。
        if (!strcmp(command, "createStream")) {
            rt->nb_streamid++;
            if (rt->nb_streamid == 0 || rt->nb_streamid == 2)
                rt->nb_streamid++; /* Values 0 and 2 are reserved */
            ff_amf_write_number(&pp, rt->nb_streamid);
            /* By now we don't control which streams are removed in
             * deleteStream. There is no stream creation control
             * if a client creates more than 2^32 - 2 streams. */
        }
    }
    spkt.size = pp - spkt.data;
    //发送响应
    ret = ff_rtmp_packet_write(rt->stream, &spkt, rt->out_chunk_size,
                               &rt->prev_pkt[1], &rt->nb_prev_pkt[1]);
    ff_rtmp_packet_destroy(&spkt);
    return ret;
}

/**
 * Read the AMF_NUMBER response ("_result") to a function call
 * (e.g. createStream()). This response should be made up of the AMF_STRING
 * "result", a NULL object and then the response encoded as AMF_NUMBER. On a
 * successful response, we will return set the value to number (otherwise number
 * will not be changed).
 *
 * @return 0 if reading the value succeeds, negative value otherwise
 */
static int read_number_result(RTMPPacket *pkt, double *number)
{
    // We only need to fit "_result" in this.
    uint8_t strbuffer[8];
    int stringlen;
    double numbuffer;
    GetByteContext gbc;

    bytestream2_init(&gbc, pkt->data, pkt->size);

    // Value 1/4: "_result" as AMF_STRING
    if (ff_amf_read_string(&gbc, strbuffer, sizeof(strbuffer), &stringlen))
        return AVERROR_INVALIDDATA;
    if (strcmp(strbuffer, "_result"))
        return AVERROR_INVALIDDATA;
    // Value 2/4: The callee reference number
    if (ff_amf_read_number(&gbc, &numbuffer))
        return AVERROR_INVALIDDATA;
    // Value 3/4: Null
    if (ff_amf_read_null(&gbc))
        return AVERROR_INVALIDDATA;
    // Value 4/4: The response as AMF_NUMBER
    if (ff_amf_read_number(&gbc, &numbuffer))
        return AVERROR_INVALIDDATA;
    else
        *number = numbuffer;

    return 0;
}

static int handle_invoke_result(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    char *tracked_method = NULL;
    int ret = 0;

    if ((ret = find_tracked_method(s, pkt, 10, &tracked_method)) < 0)
        return ret;

    if (!tracked_method) {
        /* Ignore this reply when the current method is not tracked. */
        return ret;
    }

    //connect
    if (!strcmp(tracked_method, "connect")) {
        if (!rt->is_input) {
            if ((ret = gen_release_stream(s, rt)) < 0)
                goto fail;

            if ((ret = gen_fcpublish_stream(s, rt)) < 0)
                goto fail;
        } else {
            if ((ret = gen_window_ack_size(s, rt)) < 0)
                goto fail;
        }

        if ((ret = gen_create_stream(s, rt)) < 0)
            goto fail;

        if (rt->is_input) {
            /* Send the FCSubscribe command when the name of live
             * stream is defined by the user or if it's a live stream. */
            if (rt->subscribe) {
                if ((ret = gen_fcsubscribe_stream(s, rt, rt->subscribe)) < 0)
                    goto fail;
            } else if (rt->live == -1) {
                if ((ret = gen_fcsubscribe_stream(s, rt, rt->playpath)) < 0)
                    goto fail;
            }
        }
    //createStream
    } else if (!strcmp(tracked_method, "createStream")) {
        double stream_id;
        if (read_number_result(pkt, &stream_id)) {
            av_log(s, AV_LOG_WARNING, "Unexpected reply on connect()\n");
        } else {
            rt->stream_id = stream_id;
        }

        if (!rt->is_input) {
            if ((ret = gen_publish(s, rt)) < 0)
                goto fail;
        } else {
            if (rt->live != -1) {
                if ((ret = gen_get_stream_length(s, rt)) < 0)
                    goto fail;
            }
            if ((ret = gen_play(s, rt)) < 0)
                goto fail;
            if ((ret = gen_buffer_time(s, rt)) < 0)
                goto fail;
        }
    //
    } else if (!strcmp(tracked_method, "getStreamLength")) {
        if (read_number_result(pkt, &rt->duration)) {
            av_log(s, AV_LOG_WARNING, "Unexpected reply on getStreamLength()\n");
        }
    }

fail:
    av_free(tracked_method);
    return ret;
}

static int handle_invoke_status(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    const uint8_t *data_end = pkt->data + pkt->size;
    const uint8_t *ptr = pkt->data + RTMP_HEADER;
    uint8_t tmpstr[256];
    int i, t;

    for (i = 0; i < 2; i++) {
        t = ff_amf_tag_size(ptr, data_end);
        if (t < 0)
            return 1;
        ptr += t;
    }

    t = ff_amf_get_field_value(ptr, data_end, "level", tmpstr, sizeof(tmpstr));
    if (!t && !strcmp(tmpstr, "error")) {
        t = ff_amf_get_field_value(ptr, data_end,
                                   "description", tmpstr, sizeof(tmpstr));
        if (t || !tmpstr[0])
            t = ff_amf_get_field_value(ptr, data_end, "code",
                                       tmpstr, sizeof(tmpstr));
        if (!t)
            av_log(s, AV_LOG_ERROR, "Server error: %s\n", tmpstr);
        return -1;
    }

    t = ff_amf_get_field_value(ptr, data_end, "code", tmpstr, sizeof(tmpstr));
    if (!t && !strcmp(tmpstr, "NetStream.Play.Start")) rt->state = STATE_PLAYING;
    if (!t && !strcmp(tmpstr, "NetStream.Play.Stop")) rt->state = STATE_STOPPED;
    if (!t && !strcmp(tmpstr, "NetStream.Play.UnpublishNotify")) rt->state = STATE_STOPPED;
    if (!t && !strcmp(tmpstr, "NetStream.Publish.Start")) rt->state = STATE_PUBLISHING;
    if (!t && !strcmp(tmpstr, "NetStream.Seek.Notify")) rt->state = STATE_PLAYING;

    return 0;
}

static int handle_invoke(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt = s->priv_data;
    int ret = 0;

    //TODO: check for the messages sent for wrong state?
    //这段代码是用于处理RTMP协议中的命令消息，根据命令类型的不同分别调用不同的处理函数。
    //例如"_error"表示调用方法时发生错误，"_result"表示调用方法成功，"onStatus"表示状态通知等等。
    if (ff_amf_match_string(pkt->data, pkt->size, "_error")) {
        if ((ret = handle_invoke_error(s, pkt)) < 0)
            return ret;
    } else if (ff_amf_match_string(pkt->data, pkt->size, "_result")) {
        if ((ret = handle_invoke_result(s, pkt)) < 0)
            return ret;
    } else if (ff_amf_match_string(pkt->data, pkt->size, "onStatus")) {
        if ((ret = handle_invoke_status(s, pkt)) < 0)
            return ret;
    } else if (ff_amf_match_string(pkt->data, pkt->size, "onBWDone")) {
        if ((ret = gen_check_bw(s, rt)) < 0)
            return ret;
    //流操作,执行对应的响应
    } else if (ff_amf_match_string(pkt->data, pkt->size, "releaseStream") ||
               ff_amf_match_string(pkt->data, pkt->size, "FCPublish")     ||
               ff_amf_match_string(pkt->data, pkt->size, "publish")       ||
               ff_amf_match_string(pkt->data, pkt->size, "play")          ||
               ff_amf_match_string(pkt->data, pkt->size, "_checkbw")      ||
               ff_amf_match_string(pkt->data, pkt->size, "createStream")) {
        if ((ret = send_invoke_response(s, pkt)) < 0)
            return ret;
    }

    return ret;
}

static int update_offset(RTMPContext *rt, int size)
{
    int old_flv_size;

    // generate packet header and put data into buffer for FLV demuxer
    if (rt->flv_off < rt->flv_size) {
        // There is old unread data in the buffer, thus append at the end
        old_flv_size  = rt->flv_size;
        rt->flv_size += size;
    } else {
        // All data has been read, write the new data at the start of the buffer
        old_flv_size = 0;
        rt->flv_size = size;
        rt->flv_off  = 0;
    }

    return old_flv_size;
}

static int append_flv_data(RTMPContext *rt, RTMPPacket *pkt, int skip)
{
    int old_flv_size, ret;
    PutByteContext pbc;
    const uint8_t *data = pkt->data + skip;
    const int size      = pkt->size - skip;
    uint32_t ts         = pkt->timestamp;

    if (pkt->type == RTMP_PT_AUDIO) {
        rt->has_audio = 1;
    } else if (pkt->type == RTMP_PT_VIDEO) {
        rt->has_video = 1;
    }
    //在写入FLV文件之前，代码会先更新FLV文件的偏移量，并对FLV文件的大小进行扩展。
    old_flv_size = update_offset(rt, size + 15);
    if ((ret = av_reallocp(&rt->flv_data, rt->flv_size)) < 0) {
        rt->flv_size = rt->flv_off = 0;
        return ret;
    }
    //代码会先写入一个FLV Tag Header，包括类型、数据大小、时间戳等信息，然后写入RTMP数据包中的数据内容

    bytestream2_init_writer(&pbc, rt->flv_data, rt->flv_size);
    //找到offset
    bytestream2_skip_p(&pbc, old_flv_size);
    bytestream2_put_byte(&pbc, pkt->type);
    bytestream2_put_be24(&pbc, size);
    bytestream2_put_be24(&pbc, ts);
    bytestream2_put_byte(&pbc, ts >> 24);
    bytestream2_put_be24(&pbc, 0);
    bytestream2_put_buffer(&pbc, data, size);
    bytestream2_put_be32(&pbc, size + RTMP_HEADER);

    return 0;
}

static int handle_notify(URLContext *s, RTMPPacket *pkt)
{
    RTMPContext *rt  = s->priv_data;
    uint8_t commandbuffer[64];
    char statusmsg[128];
    int stringlen, ret, skip = 0;
    GetByteContext gbc;

    bytestream2_init(&gbc, pkt->data, pkt->size);
    if (ff_amf_read_string(&gbc, commandbuffer, sizeof(commandbuffer),
                           &stringlen))
        return AVERROR_INVALIDDATA;
    //onMetaData
    //这段代码的作用是解析RTMP协议中的元数据（metadata）信息，并从中获取音视频流的编码格式等信息，以便在后续的数据交换过程中正确地处理音视频数据。
    if (!strcmp(commandbuffer, "onMetaData")) {
        // metadata properties should be stored in a mixed array
        if (bytestream2_get_byte(&gbc) == AMF_DATA_TYPE_MIXEDARRAY) {
            // We have found a metaData Array so flv can determine the streams
            // from this.
            rt->received_metadata = 1;
            // skip 32-bit max array index
            bytestream2_skip(&gbc, 4);
            while (bytestream2_get_bytes_left(&gbc) > 3) {
                if (ff_amf_get_string(&gbc, statusmsg, sizeof(statusmsg),
                                      &stringlen))
                    return AVERROR_INVALIDDATA;
                // We do not care about the content of the property (yet).
                stringlen = ff_amf_tag_size(gbc.buffer, gbc.buffer_end);
                if (stringlen < 0)
                    return AVERROR_INVALIDDATA;
                bytestream2_skip(&gbc, stringlen);

                // The presence of the following properties indicates that the
                // respective streams are present.
                //判断是否存在音视频流
                if (!strcmp(statusmsg, "videocodecid")) {
                    rt->has_video = 1;
                }
                if (!strcmp(statusmsg, "audiocodecid")) {
                    rt->has_audio = 1;
                }
            }
            if (bytestream2_get_be24(&gbc) != AMF_END_OF_OBJECT)
                return AVERROR_INVALIDDATA;
        }
    }

    // Skip the @setDataFrame string and validate it is a notification
    if (!strcmp(commandbuffer, "@setDataFrame")) {
        skip = gbc.buffer - pkt->data;
        ret = ff_amf_read_string(&gbc, statusmsg,
                                 sizeof(statusmsg), &stringlen);
        if (ret < 0)
            return AVERROR_INVALIDDATA;
    }

    return append_flv_data(rt, pkt, skip);
}

/**
 * Parse received packet and possibly perform some action depending on
 * the packet contents.
 * @return 0 for no errors, negative values for serious errors which prevent
 *         further communications, positive values for uncritical errors
 */
static int rtmp_parse_result(URLContext *s, RTMPContext *rt, RTMPPacket *pkt)
{
    int ret;

#ifdef DEBUG
    ff_rtmp_packet_dump(s, pkt);
#endif

    //根据不同的数据包类型做处理
    switch (pkt->type) {
    case RTMP_PT_BYTES_READ:
        av_log(s, AV_LOG_TRACE, "received bytes read report\n");
        break;
    case RTMP_PT_CHUNK_SIZE:
        if ((ret = handle_chunk_size(s, pkt)) < 0)
            return ret;
        break;
    case RTMP_PT_USER_CONTROL:
        if ((ret = handle_user_control(s, pkt)) < 0)
            return ret;
        break;
    case RTMP_PT_SET_PEER_BW:
        if ((ret = handle_set_peer_bw(s, pkt)) < 0)
            return ret;
        break;
    case RTMP_PT_WINDOW_ACK_SIZE:
        if ((ret = handle_window_ack_size(s, pkt)) < 0)
            return ret;
        break;
    case RTMP_PT_INVOKE:
        //amf操作
        if ((ret = handle_invoke(s, pkt)) < 0)
            return ret;
        break;
    case RTMP_PT_VIDEO:
    case RTMP_PT_AUDIO:
    case RTMP_PT_METADATA:
    case RTMP_PT_NOTIFY:
        /* Audio, Video and Metadata packets are parsed in get_packet() */
        break;
    default:
        av_log(s, AV_LOG_VERBOSE, "Unknown packet type received 0x%02X\n", pkt->type);
        break;
    }
    return 0;
}

//这段代码的作用是处理从RTMP协议的元数据（metadata）包中获取的音视频数据，并将其写入FLV文件格式的数据中
static int handle_metadata(RTMPContext *rt, RTMPPacket *pkt)
{
    int ret, old_flv_size, type;
    const uint8_t *next;
    uint8_t *p;
    uint32_t size;
    uint32_t ts, cts, pts = 0;

    old_flv_size = update_offset(rt, pkt->size);

    if ((ret = av_reallocp(&rt->flv_data, rt->flv_size)) < 0) {
        rt->flv_size = rt->flv_off = 0;
        return ret;
    }

    next = pkt->data;
    p    = rt->flv_data + old_flv_size;

    /* copy data while rewriting timestamps */
    ts = pkt->timestamp;

    while (next - pkt->data < pkt->size - RTMP_HEADER) {
        type = bytestream_get_byte(&next);
        size = bytestream_get_be24(&next);
        cts  = bytestream_get_be24(&next);
        cts |= bytestream_get_byte(&next) << 24;
        if (!pts)
            pts = cts;
        ts += cts - pts;
        pts = cts;
        if (size + 3 + 4 > pkt->data + pkt->size - next)
            break;
        //写入元数据
        bytestream_put_byte(&p, type);
        bytestream_put_be24(&p, size);
        bytestream_put_be24(&p, ts);
        bytestream_put_byte(&p, ts >> 24);
        memcpy(p, next, size + 3 + 4);
        p    += size + 3;
        bytestream_put_be32(&p, size + RTMP_HEADER);
        next += size + 3 + 4;
    }
    if (p != rt->flv_data + rt->flv_size) {
        av_log(rt, AV_LOG_WARNING, "Incomplete flv packets in "
                                     "RTMP_PT_METADATA packet\n");
        rt->flv_size = p - rt->flv_data;
    }

    return 0;
}

/**
 * Interact with the server by receiving and sending RTMP packets until
 * there is some significant data (media data or expected status notification).
 *
 * @param s          reading context
 * @param for_header non-zero value tells function to work until it
 * gets notification from the server that playing has been started,
 * otherwise function will work until some media data is received (or
 * an error happens)
 * @return 0 for successful operation, negative value in case of error
 */
static int get_packet(URLContext *s, int for_header)
{
    RTMPContext *rt = s->priv_data;
    int ret;

    if (rt->state == STATE_STOPPED)
        return AVERROR_EOF;

    for (;;) {
        RTMPPacket rpkt = { 0 };
        //读取一个message
        if ((ret = ff_rtmp_packet_read(rt->stream, &rpkt,
                                       rt->in_chunk_size, &rt->prev_pkt[0],
                                       &rt->nb_prev_pkt[0])) <= 0) {
            if (ret == 0) {
                return AVERROR(EAGAIN);
            } else {
                return AVERROR(EIO);
            }
        }

        // Track timestamp for later use
        rt->last_timestamp = rpkt.timestamp;

        rt->bytes_read += ret;

        if (rt->bytes_read - rt->last_bytes_read > rt->receive_report_size) {
            av_log(s, AV_LOG_DEBUG, "Sending bytes read report\n");
            if ((ret = gen_bytes_read(s, rt, rpkt.timestamp + 1)) < 0) {
                ff_rtmp_packet_destroy(&rpkt);
                return ret;
            }
            rt->last_bytes_read = rt->bytes_read;
        }
        //处理接收到的命令消息和流控信息
        ret = rtmp_parse_result(s, rt, &rpkt);

        // At this point we must check if we are in the seek state and continue
        // with the next packet. handle_invoke will get us out of this state
        // when the right message is encountered
        if (rt->state == STATE_SEEKING) {
            ff_rtmp_packet_destroy(&rpkt);
            // We continue, let the natural flow of things happen:
            // AVERROR(EAGAIN) or handle_invoke gets us out of here
            continue;
        }

        if (ret < 0) {//serious error in current packet
            ff_rtmp_packet_destroy(&rpkt);
            return ret;
        }
        if (rt->do_reconnect && for_header) {
            ff_rtmp_packet_destroy(&rpkt);
            return 0;
        }
        if (rt->state == STATE_STOPPED) {
            ff_rtmp_packet_destroy(&rpkt);
            return AVERROR_EOF;
        }

        if (for_header && (rt->state == STATE_PLAYING    ||
                           rt->state == STATE_PUBLISHING ||
                           rt->state == STATE_SENDING    ||
                           rt->state == STATE_RECEIVING)) {
            ff_rtmp_packet_destroy(&rpkt);
            return 0;
        }
        if (!rpkt.size || !rt->is_input) {
            ff_rtmp_packet_destroy(&rpkt);
            continue;
        }

        //处理媒体数据
        if (rpkt.type == RTMP_PT_VIDEO || rpkt.type == RTMP_PT_AUDIO) {
            //读取flb
            ret = append_flv_data(rt, &rpkt, 0);
            ff_rtmp_packet_destroy(&rpkt);
            return ret;
        } else if (rpkt.type == RTMP_PT_NOTIFY) {
            //处理通知
            ret = handle_notify(s, &rpkt);
            ff_rtmp_packet_destroy(&rpkt);
            return ret;
        } else if (rpkt.type == RTMP_PT_METADATA) {
            //处理元数据
            ret = handle_metadata(rt, &rpkt);
            ff_rtmp_packet_destroy(&rpkt);
            return ret;
        }
        ff_rtmp_packet_destroy(&rpkt);
    }
}

static int rtmp_close(URLContext *h)
{
    RTMPContext *rt = h->priv_data;
    int ret = 0, i, j;

    if (!rt->is_input) {
        rt->flv_data = NULL;
        if (rt->out_pkt.size)
            ff_rtmp_packet_destroy(&rt->out_pkt);
        if (rt->state > STATE_FCPUBLISH)
            ret = gen_fcunpublish_stream(h, rt);
    }
    if (rt->state > STATE_HANDSHAKED)
        ret = gen_delete_stream(h, rt);
    for (i = 0; i < 2; i++) {
        for (j = 0; j < rt->nb_prev_pkt[i]; j++)
            ff_rtmp_packet_destroy(&rt->prev_pkt[i][j]);
        av_freep(&rt->prev_pkt[i]);
    }

    free_tracked_methods(rt);
    av_freep(&rt->flv_data);
    ffurl_closep(&rt->stream);
    return ret;
}

/**
 * Insert a fake onMetadata packet into the FLV stream to notify the FLV
 * demuxer about the duration of the stream.
 *
 * This should only be done if there was no real onMetadata packet sent by the
 * server at the start of the stream and if we were able to retrieve a valid
 * duration via a getStreamLength call.
 *
 * @return 0 for successful operation, negative value in case of error
 */
static int inject_fake_duration_metadata(RTMPContext *rt)
{
    // We need to insert the metadata packet directly after the FLV
    // header, i.e. we need to move all other already read data by the
    // size of our fake metadata packet.

    uint8_t* p;
    // Keep old flv_data pointer
    uint8_t* old_flv_data = rt->flv_data;
    // Allocate a new flv_data pointer with enough space for the additional package
    if (!(rt->flv_data = av_malloc(rt->flv_size + 55))) {
        rt->flv_data = old_flv_data;
        return AVERROR(ENOMEM);
    }

    // Copy FLV header
    memcpy(rt->flv_data, old_flv_data, 13);
    // Copy remaining packets
    memcpy(rt->flv_data + 13 + 55, old_flv_data + 13, rt->flv_size - 13);
    // Increase the size by the injected packet
    rt->flv_size += 55;
    // Delete the old FLV data
    av_freep(&old_flv_data);

    p = rt->flv_data + 13;
    bytestream_put_byte(&p, FLV_TAG_TYPE_META);
    bytestream_put_be24(&p, 40); // size of data part (sum of all parts below)
    bytestream_put_be24(&p, 0);  // timestamp
    bytestream_put_be32(&p, 0);  // reserved

    // first event name as a string
    bytestream_put_byte(&p, AMF_DATA_TYPE_STRING);
    // "onMetaData" as AMF string
    bytestream_put_be16(&p, 10);
    bytestream_put_buffer(&p, "onMetaData", 10);

    // mixed array (hash) with size and string/type/data tuples
    bytestream_put_byte(&p, AMF_DATA_TYPE_MIXEDARRAY);
    bytestream_put_be32(&p, 1); // metadata_count

    // "duration" as AMF string
    bytestream_put_be16(&p, 8);
    bytestream_put_buffer(&p, "duration", 8);
    bytestream_put_byte(&p, AMF_DATA_TYPE_NUMBER);
    bytestream_put_be64(&p, av_double2int(rt->duration));

    // Finalise object
    bytestream_put_be16(&p, 0); // Empty string
    bytestream_put_byte(&p, AMF_END_OF_OBJECT);
    bytestream_put_be32(&p, 40 + RTMP_HEADER); // size of data part (sum of all parts above)

    return 0;
}

/**
 * Open RTMP connection and verify that the stream can be played.
 *
 * URL syntax: rtmp://server[:port][/app][/playpath]
 *             where 'app' is first one or two directories in the path
 *             (e.g. /ondemand/, /flash/live/, etc.)
 *             and 'playpath' is a file name (the rest of the path,
 *             may be prefixed with "mp4:")
 */
static int rtmp_open(URLContext *s, const char *uri, int flags, AVDictionary **opts)
{

    RTMPContext *rt = s->priv_data;
    char proto[8], hostname[256], path[1024], auth[100], *fname;
    char *old_app, *qmark, *n, fname_buffer[1024];
    uint8_t buf[2048];
    int port;
    int ret;

    if (rt->listen_timeout > 0)
        rt->listen = 1;

    rt->is_input = !(flags & AVIO_FLAG_WRITE);
    //解析url
    av_url_split(proto, sizeof(proto), auth, sizeof(auth),
                 hostname, sizeof(hostname), &port,
                 path, sizeof(path), s->filename);

    n = strchr(path, ' ');
    if (n) {
        av_log(s, AV_LOG_WARNING,
               "Detected librtmp style URL parameters, these aren't supported "
               "by the libavformat internal RTMP handler currently enabled. "
               "See the documentation for the correct way to pass parameters.\n");
        *n = '\0'; // Trim not supported part
    }

    if (auth[0]) {
        char *ptr = strchr(auth, ':');
        if (ptr) {
            *ptr = '\0';
            av_strlcpy(rt->username, auth, sizeof(rt->username));
            av_strlcpy(rt->password, ptr + 1, sizeof(rt->password));
        }
    }

    if (rt->listen && strcmp(proto, "rtmp")) {
        av_log(s, AV_LOG_ERROR, "rtmp_listen not available for %s\n",
               proto);
        return AVERROR(EINVAL);
    }
    //代码根据 URI 中的协议类型（proto）来判断是否需要使用 HTTP 隧道传输（rtmpt 或 rtmpts）或者加密传输（rtmpe 或 rtmpte）。
    if (!strcmp(proto, "rtmpt") || !strcmp(proto, "rtmpts")) {
        if (!strcmp(proto, "rtmpts"))
            av_dict_set(opts, "ffrtmphttp_tls", "1", 1);

        /* open the http tunneling connection */
        ff_url_join(buf, sizeof(buf), "ffrtmphttp", NULL, hostname, port, NULL);
    } else if (!strcmp(proto, "rtmps")) {
        /* open the tls connection */
        if (port < 0)
            port = RTMPS_DEFAULT_PORT;
        ff_url_join(buf, sizeof(buf), "tls", NULL, hostname, port, NULL);
    } else if (!strcmp(proto, "rtmpe") || (!strcmp(proto, "rtmpte"))) {
        if (!strcmp(proto, "rtmpte"))
            av_dict_set(opts, "ffrtmpcrypt_tunneling", "1", 1);

        /* open the encrypted connection */
        ff_url_join(buf, sizeof(buf), "ffrtmpcrypt", NULL, hostname, port, NULL);
        rt->encrypted = 1;
    //如果 URI 的协议类型既不是 rtmpt、rtmpts、rtmps，也不是 rtmpe、rtmpte，
    // 则默认使用 TCP 协议连接 RTMP 服务器，并将 tcp 协议与主机名和端口号拼接成新的 URI。
    } else {
        /* open the tcp connection */
        if (port < 0)
            port = RTMP_DEFAULT_PORT;
        //
        if (rt->listen)
            ff_url_join(buf, sizeof(buf), "tcp", NULL, hostname, port,
                        "?listen&listen_timeout=%d",
                        rt->listen_timeout * 1000);
        else
            ff_url_join(buf, sizeof(buf), "tcp", NULL, hostname, port, NULL);
    }

reconnect:
    //
    if ((ret = ffurl_open_whitelist(&rt->stream, buf, AVIO_FLAG_READ_WRITE,
                                    &s->interrupt_callback, opts,
                                    s->protocol_whitelist, s->protocol_blacklist, s)) < 0) {
        av_log(s , AV_LOG_ERROR, "Cannot open connection %s\n", buf);
        goto fail;
    }

    if (rt->swfverify) {
        if ((ret = rtmp_calc_swfhash(s)) < 0)
            goto fail;
    }

    //start状态
    rt->state = STATE_START;
    //握手
    if (!rt->listen && (ret = rtmp_handshake(s, rt)) < 0)
        goto fail;
    if (rt->listen && (ret = rtmp_server_handshake(s, rt)) < 0)
        goto fail;

    //初始化chunksize
    rt->out_chunk_size = 128;
    rt->in_chunk_size  = 128; // Probably overwritten later
    //handshaked状态
    rt->state = STATE_HANDSHAKED;

    // Keep the application name when it has been defined by the user.
    old_app = rt->app;

    rt->app = av_malloc(APP_MAX_LENGTH);
    if (!rt->app) {
        ret = AVERROR(ENOMEM);
        goto fail;
    }

    //extract "app" part from path
    //rtmp://example.com/live/stream：表示 RTMP 协议的流媒体 URL，
    // 其中 example.com 是服务器的域名或 IP 地址，live 是应用程序名称，stream 是播放路径（也可以是流名称）
    //这段代码是 RTMP 协议中用于解析 URL 中的路径部分，并从中提取出应用程序名称（app）和播放路径（playpath）的过程。
    qmark = strchr(path, '?');
    //首先判断 URL 中是否包含参数 slist，如果包含，则将完整路径作为应用程序名称（app），将 slist 后面的路径作为播放路径（playpath）
    if (qmark && strstr(qmark, "slist=")) {
        char* amp;
        // After slist we have the playpath, the full path is used as app
        av_strlcpy(rt->app, path + 1, APP_MAX_LENGTH);
        fname = strstr(path, "slist=") + 6;
        // Strip any further query parameters from fname
        amp = strchr(fname, '&');
        if (amp) {
            av_strlcpy(fname_buffer, fname, FFMIN(amp - fname + 1,
                                                  sizeof(fname_buffer)));
            fname = fname_buffer;
        }
    //如果路径以 /ondemand/ 开头，则将 ondemand 作为应用程序名称（app），将 /ondemand/ 后面的路径作为播放路径（playpath）。
    } else if (!strncmp(path, "/ondemand/", 10)) {
        fname = path + 10;
        memcpy(rt->app, "ondemand", 9);
    //如果路径中包含多个斜杠 /，则将第一个斜杠后面的路径作为应用程序名称（app），将第二个斜杠后面的路径作为播放路径（playpath）
    } else {
        char *next = *path ? path + 1 : path;
        char *p = strchr(next, '/');
        if (!p) {
            if (old_app) {
                // If name of application has been defined by the user, assume that
                // playpath is provided in the URL
                fname = next;
            } else {
                fname = NULL;
                av_strlcpy(rt->app, next, APP_MAX_LENGTH);
            }
        //如果路径中只有一个斜杠 /，则根据是否已经定义应用程序名称来判断应用程序名称和播放路径。
        // 如果已经定义了应用程序名称，则将路径中斜杠后面的路径作为播放路径；否则将整个路径作为应用程序名称。
        } else {
            // make sure we do not mismatch a playpath for an application instance
            char *c = strchr(p + 1, ':');
            fname = strchr(p + 1, '/');
            if (!fname || (c && c < fname)) {
                fname = p + 1;
                av_strlcpy(rt->app, path + 1, FFMIN(p - path, APP_MAX_LENGTH));
            } else {
                fname++;
                av_strlcpy(rt->app, path + 1, FFMIN(fname - path - 1, APP_MAX_LENGTH));
            }
        }
    }
    //最后，如果已经定义了应用程序名称，则使用用户定义的应用程序名称覆盖之前提取的应用程序名称。
    if (old_app) {
        // The name of application has been defined by the user, override it.
        if (strlen(old_app) >= APP_MAX_LENGTH) {
            ret = AVERROR(EINVAL);
            goto fail;
        }
        av_free(rt->app);
        rt->app = old_app;
    }

    //保存播放路径
    if (!rt->playpath) {
        int max_len = 1;
        if (fname)
            max_len = strlen(fname) + 5; // add prefix "mp4:"
        rt->playpath = av_malloc(max_len);
        if (!rt->playpath) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }

        //当文件名为 "example.mp4" 时，根据代码的逻辑，播放路径会被设置为 "mp4:example.mp4"。这是因为文件名以 ".mp4" 结尾，
        // 符合 MP4 文件的命名规则，因此播放路径需要以 "mp4:" 开头，表示要播放一个 MP4 文件，后面跟着文件名。
        //
        //当文件名为 "example.flv" 时，根据代码的逻辑，播放路径会被设置为 "example"。
        // 这是因为文件名以 ".flv" 结尾，符合 FLV 文件的命名规则，因此播放路径只需要使用文件名本身，不需要额外的前缀或后缀。
        if (fname) {
            int len = strlen(fname);
            //mp4和f4v的播放路径
            if (!strchr(fname, ':') && len >= 4 &&
                (!strcmp(fname + len - 4, ".f4v") ||
                 !strcmp(fname + len - 4, ".mp4"))) {
                memcpy(rt->playpath, "mp4:", 5);
            } else {
                if (len >= 4 && !strcmp(fname + len - 4, ".flv"))
                    fname[len - 4] = '\0';
                rt->playpath[0] = 0;
            }
            av_strlcat(rt->playpath, fname, max_len);
        } else {
            rt->playpath[0] = '\0';
        }
    }
    //目的是根据 RTMP 协议的参数设置 RTMP 连接的地址（tcurl）。
    if (!rt->tcurl) {
        rt->tcurl = av_malloc(TCURL_MAX_LENGTH);
        if (!rt->tcurl) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        ff_url_join(rt->tcurl, TCURL_MAX_LENGTH, proto, NULL, hostname,
                    port, "/%s", rt->app);
    }

    //插件版本
    if (!rt->flashver) {
        rt->flashver = av_malloc(FLASHVER_MAX_LENGTH);
        if (!rt->flashver) {
            ret = AVERROR(ENOMEM);
            goto fail;
        }
        if (rt->is_input) {
            snprintf(rt->flashver, FLASHVER_MAX_LENGTH, "%s %d,%d,%d,%d",
                    RTMP_CLIENT_PLATFORM, RTMP_CLIENT_VER1, RTMP_CLIENT_VER2,
                    RTMP_CLIENT_VER3, RTMP_CLIENT_VER4);
        } else {
            snprintf(rt->flashver, FLASHVER_MAX_LENGTH,
                    "FMLE/3.0 (compatible; %s)", LIBAVFORMAT_IDENT);
        }
    }

    rt->receive_report_size = 1048576;
    rt->bytes_read = 0;
    rt->has_audio = 0;
    rt->has_video = 0;
    rt->received_metadata = 0;
    rt->last_bytes_read = 0;
    rt->max_sent_unacked = 2500000;
    rt->duration = 0;

    av_log(s, AV_LOG_DEBUG, "Proto = %s, path = %s, app = %s, fname = %s\n",
           proto, path, rt->app, rt->playpath);
    //发起连接
    if (!rt->listen) {
        if ((ret = gen_connect(s, rt)) < 0)
            goto fail;
    //接收连接
    } else {
        if ((ret = read_connect(s, s->priv_data)) < 0)
            goto fail;
    }

    //读取第一个数据包
    do {
        ret = get_packet(s, 1);
    } while (ret == AVERROR(EAGAIN));
    if (ret < 0)
        goto fail;

    //如果 rt->do_reconnect 标志被设置，表示需要重新连接 RTMP 服务器，则关闭当前连接，清除相关状态信息，然后跳转到重新连接 RTMP 服务器的代码块。
    if (rt->do_reconnect) {
        int i;
        ffurl_closep(&rt->stream);
        rt->do_reconnect = 0;
        rt->nb_invokes   = 0;
        for (i = 0; i < 2; i++)
            memset(rt->prev_pkt[i], 0,
                   sizeof(**rt->prev_pkt) * rt->nb_prev_pkt[i]);
        free_tracked_methods(rt);
        goto reconnect;
    }

    //接收流的一端生成flv头信息
    if (rt->is_input) {
        // generate FLV header for demuxer
        rt->flv_size = 13;
        if ((ret = av_reallocp(&rt->flv_data, rt->flv_size)) < 0)
            goto fail;
        rt->flv_off  = 0;
        memcpy(rt->flv_data, "FLV\1\0\0\0\0\011\0\0\0\0", rt->flv_size);

        // Read packets until we reach the first A/V packet or read metadata.
        // If there was a metadata package in front of the A/V packets, we can
        // build the FLV header from this. If we do not receive any metadata,
        // the FLV decoder will allocate the needed streams when their first
        // audio or video packet arrives.
        while (!rt->has_audio && !rt->has_video && !rt->received_metadata) {
            if ((ret = get_packet(s, 0)) < 0)
               goto fail;
        }

        // Either after we have read the metadata or (if there is none) the
        // first packet of an A/V stream, we have a better knowledge about the
        // streams, so set the FLV header accordingly.
        if (rt->has_audio) {
            rt->flv_data[4] |= FLV_HEADER_FLAG_HASAUDIO;
        }
        if (rt->has_video) {
            rt->flv_data[4] |= FLV_HEADER_FLAG_HASVIDEO;
        }

        // If we received the first packet of an A/V stream and no metadata but
        // the server returned a valid duration, create a fake metadata packet
        // to inform the FLV decoder about the duration.
        if (!rt->received_metadata && rt->duration > 0) {
            if ((ret = inject_fake_duration_metadata(rt)) < 0)
                goto fail;
        }
    //输出
    //如果 rt->is_input 标志没有被设置，表示这是输出模块，需要将数据写入到 RTMP 服务器。在这种情况下，rt->flv_data 缓冲区为空，不需要生成 FLV 格式的数据。
    // rt->skip_bytes 表示需要跳过的字节数，这是因为在写入 FLV 文件时需要跳过 FLV 头部的数据。
    } else {
        rt->flv_size = 0;
        rt->flv_data = NULL;
        rt->flv_off  = 0;
        rt->skip_bytes = 13;
    }

    s->max_packet_size = rt->stream->max_packet_size;
    s->is_streamed     = 1;
    return 0;

fail:
    av_freep(&rt->playpath);
    av_freep(&rt->tcurl);
    av_freep(&rt->flashver);
    av_dict_free(opts);
    rtmp_close(s);
    return ret;
}

//读取数据
static int rtmp_read(URLContext *s, uint8_t *buf, int size)
{
    RTMPContext *rt = s->priv_data;
    int orig_size = size;
    int ret;

    while (size > 0) {
        int data_left = rt->flv_size - rt->flv_off;

        if (data_left >= size) {
            memcpy(buf, rt->flv_data + rt->flv_off, size);
            rt->flv_off += size;
            return orig_size;
        }
        //buf没有数据了.
        if (data_left > 0) {
            memcpy(buf, rt->flv_data + rt->flv_off, data_left);
            buf  += data_left;
            size -= data_left;
            rt->flv_off = rt->flv_size;
            return data_left;
        }
        //buf为空,则读取数据
        if ((ret = get_packet(s, 0)) < 0)
           return ret;
    }
    return orig_size;
}

static int64_t rtmp_seek(URLContext *s, int stream_index, int64_t timestamp,
                         int flags)
{
    RTMPContext *rt = s->priv_data;
    int ret;
    av_log(s, AV_LOG_DEBUG,
           "Seek on stream index %d at timestamp %"PRId64" with flags %08x\n",
           stream_index, timestamp, flags);
    //seek
    if ((ret = gen_seek(s, rt, timestamp)) < 0) {
        av_log(s, AV_LOG_ERROR,
               "Unable to send seek command on stream index %d at timestamp "
               "%"PRId64" with flags %08x\n",
               stream_index, timestamp, flags);
        return ret;
    }
    rt->flv_off = rt->flv_size;
    rt->state = STATE_SEEKING;
    return timestamp;
}

static int rtmp_pause(URLContext *s, int pause)
{
    RTMPContext *rt = s->priv_data;
    int ret;
    av_log(s, AV_LOG_DEBUG, "Pause at timestamp %d\n",
           rt->last_timestamp);
    if ((ret = gen_pause(s, rt, pause, rt->last_timestamp)) < 0) {
        av_log(s, AV_LOG_ERROR, "Unable to send pause command at timestamp %d\n",
               rt->last_timestamp);
        return ret;
    }
    return 0;
}

static int rtmp_write(URLContext *s, const uint8_t *buf, int size)
{
    RTMPContext *rt = s->priv_data;
    int size_temp = size;
    int pktsize, pkttype, copy;
    uint32_t ts;
    const uint8_t *buf_temp = buf;
    uint8_t c;
    int ret;

    do {
        if (rt->skip_bytes) {
            int skip = FFMIN(rt->skip_bytes, size_temp);
            buf_temp       += skip;
            size_temp      -= skip;
            rt->skip_bytes -= skip;
            continue;
        }

        if (rt->flv_header_bytes < RTMP_HEADER) {
            const uint8_t *header = rt->flv_header;
            int channel = RTMP_AUDIO_CHANNEL;

            copy = FFMIN(RTMP_HEADER - rt->flv_header_bytes, size_temp);
            bytestream_get_buffer(&buf_temp, rt->flv_header + rt->flv_header_bytes, copy);
            rt->flv_header_bytes += copy;
            size_temp            -= copy;
            if (rt->flv_header_bytes < RTMP_HEADER)
                break;

            pkttype = bytestream_get_byte(&header);
            pktsize = bytestream_get_be24(&header);
            ts = bytestream_get_be24(&header);
            ts |= bytestream_get_byte(&header) << 24;
            bytestream_get_be24(&header);
            rt->flv_size = pktsize;

            if (pkttype == RTMP_PT_VIDEO)
                channel = RTMP_VIDEO_CHANNEL;

            if (((pkttype == RTMP_PT_VIDEO || pkttype == RTMP_PT_AUDIO) && ts == 0) ||
                pkttype == RTMP_PT_NOTIFY) {
                if ((ret = ff_rtmp_check_alloc_array(&rt->prev_pkt[1],
                                                     &rt->nb_prev_pkt[1],
                                                     channel)) < 0)
                    return ret;
                // Force sending a full 12 bytes header by clearing the
                // channel id, to make it not match a potential earlier
                // packet in the same channel.
                rt->prev_pkt[1][channel].channel_id = 0;
            }

            //this can be a big packet, it's better to send it right here
            if ((ret = ff_rtmp_packet_create(&rt->out_pkt, channel,
                                             pkttype, ts, pktsize)) < 0)
                return ret;

            rt->out_pkt.extra = rt->stream_id;
            rt->flv_data = rt->out_pkt.data;
        }

        copy = FFMIN(rt->flv_size - rt->flv_off, size_temp);
        bytestream_get_buffer(&buf_temp, rt->flv_data + rt->flv_off, copy);
        rt->flv_off += copy;
        size_temp   -= copy;

        if (rt->flv_off == rt->flv_size) {
            rt->skip_bytes = 4;

            if (rt->out_pkt.type == RTMP_PT_NOTIFY) {
                // For onMetaData and |RtmpSampleAccess packets, we want
                // @setDataFrame prepended to the packet before it gets sent.
                // However, not all RTMP_PT_NOTIFY packets (e.g., onTextData
                // and onCuePoint).
                uint8_t commandbuffer[64];
                int stringlen = 0;
                GetByteContext gbc;

                bytestream2_init(&gbc, rt->flv_data, rt->flv_size);
                if (!ff_amf_read_string(&gbc, commandbuffer, sizeof(commandbuffer),
                                        &stringlen)) {
                    if (!strcmp(commandbuffer, "onMetaData") ||
                        !strcmp(commandbuffer, "|RtmpSampleAccess")) {
                        uint8_t *ptr;
                        if ((ret = av_reallocp(&rt->out_pkt.data, rt->out_pkt.size + 16)) < 0) {
                            rt->flv_size = rt->flv_off = rt->flv_header_bytes = 0;
                            return ret;
                        }
                        memmove(rt->out_pkt.data + 16, rt->out_pkt.data, rt->out_pkt.size);
                        rt->out_pkt.size += 16;
                        ptr = rt->out_pkt.data;
                        ff_amf_write_string(&ptr, "@setDataFrame");
                    }
                }
            }

            if ((ret = rtmp_send_packet(rt, &rt->out_pkt, 0)) < 0)
                return ret;
            rt->flv_size = 0;
            rt->flv_off = 0;
            rt->flv_header_bytes = 0;
            rt->flv_nb_packets++;
        }
    } while (buf_temp - buf < size);

    if (rt->flv_nb_packets < rt->flush_interval)
        return size;
    rt->flv_nb_packets = 0;

    /* set stream into nonblocking mode */
    rt->stream->flags |= AVIO_FLAG_NONBLOCK;

    /* try to read one byte from the stream */
    ret = ffurl_read(rt->stream, &c, 1);

    /* switch the stream back into blocking mode */
    rt->stream->flags &= ~AVIO_FLAG_NONBLOCK;

    if (ret == AVERROR(EAGAIN)) {
        /* no incoming data to handle */
        return size;
    } else if (ret < 0) {
        return ret;
    } else if (ret == 1) {
        RTMPPacket rpkt = { 0 };

        if ((ret = ff_rtmp_packet_read_internal(rt->stream, &rpkt,
                                                rt->in_chunk_size,
                                                &rt->prev_pkt[0],
                                                &rt->nb_prev_pkt[0], c)) <= 0)
             return ret;

        if ((ret = rtmp_parse_result(s, rt, &rpkt)) < 0)
            return ret;

        ff_rtmp_packet_destroy(&rpkt);
    }

    return size;
}

#define OFFSET(x) offsetof(RTMPContext, x)
#define DEC AV_OPT_FLAG_DECODING_PARAM
#define ENC AV_OPT_FLAG_ENCODING_PARAM

//rtmp选项
static const AVOption rtmp_options[] = {
    {"rtmp_app", "Name of application to connect to on the RTMP server", OFFSET(app), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_buffer", "Set buffer time in milliseconds. The default is 3000.", OFFSET(client_buffer_time), AV_OPT_TYPE_INT, {.i64 = 3000}, 0, INT_MAX, DEC|ENC},
    {"rtmp_conn", "Append arbitrary AMF data to the Connect message", OFFSET(conn), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_flashver", "Version of the Flash plugin used to run the SWF player.", OFFSET(flashver), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_flush_interval", "Number of packets flushed in the same request (RTMPT only).", OFFSET(flush_interval), AV_OPT_TYPE_INT, {.i64 = 10}, 0, INT_MAX, ENC},
    {"rtmp_live", "Specify that the media is a live stream.", OFFSET(live), AV_OPT_TYPE_INT, {.i64 = -2}, INT_MIN, INT_MAX, DEC, "rtmp_live"},
    {"any", "both", 0, AV_OPT_TYPE_CONST, {.i64 = -2}, 0, 0, DEC, "rtmp_live"},
    {"live", "live stream", 0, AV_OPT_TYPE_CONST, {.i64 = -1}, 0, 0, DEC, "rtmp_live"},
    {"recorded", "recorded stream", 0, AV_OPT_TYPE_CONST, {.i64 = 0}, 0, 0, DEC, "rtmp_live"},
    {"rtmp_pageurl", "URL of the web page in which the media was embedded. By default no value will be sent.", OFFSET(pageurl), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC},
    {"rtmp_playpath", "Stream identifier to play or to publish", OFFSET(playpath), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_subscribe", "Name of live stream to subscribe to. Defaults to rtmp_playpath.", OFFSET(subscribe), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC},
    {"rtmp_swfhash", "SHA256 hash of the decompressed SWF file (32 bytes).", OFFSET(swfhash), AV_OPT_TYPE_BINARY, .flags = DEC},
    {"rtmp_swfsize", "Size of the decompressed SWF file, required for SWFVerification.", OFFSET(swfsize), AV_OPT_TYPE_INT, {.i64 = 0}, 0, INT_MAX, DEC},
    {"rtmp_swfurl", "URL of the SWF player. By default no value will be sent", OFFSET(swfurl), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_swfverify", "URL to player swf file, compute hash/size automatically.", OFFSET(swfverify), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC},
    {"rtmp_tcurl", "URL of the target stream. Defaults to proto://host[:port]/app.", OFFSET(tcurl), AV_OPT_TYPE_STRING, {.str = NULL }, 0, 0, DEC|ENC},
    {"rtmp_listen", "Listen for incoming rtmp connections", OFFSET(listen), AV_OPT_TYPE_INT, {.i64 = 0}, INT_MIN, INT_MAX, DEC, "rtmp_listen" },
    {"listen",      "Listen for incoming rtmp connections", OFFSET(listen), AV_OPT_TYPE_INT, {.i64 = 0}, INT_MIN, INT_MAX, DEC, "rtmp_listen" },
    {"timeout", "Maximum timeout (in seconds) to wait for incoming connections. -1 is infinite. Implies -rtmp_listen 1",  OFFSET(listen_timeout), AV_OPT_TYPE_INT, {.i64 = -1}, INT_MIN, INT_MAX, DEC, "rtmp_listen" },
    { NULL },
};

#define RTMP_PROTOCOL(flavor)                    \
static const AVClass flavor##_class = {          \
    .class_name = #flavor,                       \
    .item_name  = av_default_item_name,          \
    .option     = rtmp_options,                  \
    .version    = LIBAVUTIL_VERSION_INT,         \
};                                               \
                                                 \
const URLProtocol ff_##flavor##_protocol = {     \
    .name           = #flavor,                   \
    .url_open2      = rtmp_open,                 \
    .url_read       = rtmp_read,                 \
    .url_read_seek  = rtmp_seek,                 \
    .url_read_pause = rtmp_pause,                \
    .url_write      = rtmp_write,                \
    .url_close      = rtmp_close,                \
    .priv_data_size = sizeof(RTMPContext),       \
    .flags          = URL_PROTOCOL_FLAG_NETWORK, \
    .priv_data_class= &flavor##_class,           \
};


RTMP_PROTOCOL(rtmp)
RTMP_PROTOCOL(rtmpe)
RTMP_PROTOCOL(rtmps)
RTMP_PROTOCOL(rtmpt)
RTMP_PROTOCOL(rtmpte)
RTMP_PROTOCOL(rtmpts)
