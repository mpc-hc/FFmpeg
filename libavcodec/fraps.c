/*
 * Fraps FPS1 decoder
 * Copyright (c) 2005 Roine Gustafsson
 * Copyright (c) 2006 Konstantin Shishkov
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
 * Lossless Fraps 'FPS1' decoder
 * @author Roine Gustafsson (roine at users sf net)
 * @author Konstantin Shishkov
 *
 * Codec algorithm for version 0 is taken from Transcode <www.transcoding.org>
 *
 * Version 2 files support by Konstantin Shishkov
 */

#include "avcodec.h"
#include "internal.h"
#include "get_bits.h"
#include "huffman.h"
#include "bytestream.h"
#include "dsputil.h"
#include "thread.h"
#include "libavutil/imgutils.h"

#define FPS_TAG MKTAG('F', 'P', 'S', 'x')

/**
 * local variable storage
 */
typedef struct FrapsContext{
    AVCodecContext *avctx;
    int cur_index, prev_index;
    int next_cur_index, next_prev_index;
    AVFrame buf_ptrs[2];
    uint8_t *tmpbuf;
    int tmpbuf_size;
    DSPContext dsp;
} FrapsContext;


/**
 * initializes decoder
 * @param avctx codec context
 * @return 0 on success or negative if fails
 */
static av_cold int decode_init(AVCodecContext *avctx)
{
    FrapsContext * const s = avctx->priv_data;

    avcodec_get_frame_defaults(&s->buf_ptrs[0]);
    avcodec_get_frame_defaults(&s->buf_ptrs[1]);

    s->prev_index = 0;
    s->cur_index = 1;

    s->avctx = avctx;
    s->tmpbuf = NULL;

    ff_dsputil_init(&s->dsp, avctx);

    return 0;
}

static int fraps_decode_update_thread_context(AVCodecContext *avctx, const AVCodecContext *avctx_from)
{
    FrapsContext *dst = avctx->priv_data, *src = avctx_from->priv_data;

    if (avctx == avctx_from) return 0;

    dst->cur_index  = src->next_cur_index;
    dst->prev_index = src->next_prev_index;

    memcpy(dst->buf_ptrs, src->buf_ptrs, sizeof(src->buf_ptrs));

    memset(&dst->buf_ptrs[dst->cur_index], 0, sizeof(AVFrame));

    return 0;
}

/**
 * Comparator - our nodes should ascend by count
 * but with preserved symbol order
 */
static int huff_cmp(const void *va, const void *vb){
    const Node *a = va, *b = vb;
    return (a->count - b->count)*256 + a->sym - b->sym;
}

/**
 * decode Fraps v2 packed plane
 */
static int fraps2_decode_plane(FrapsContext *s, uint8_t *dst, int stride, int w,
                               int h, const uint8_t *src, int size, int Uoff,
                               const int step)
{
    int i, j;
    GetBitContext gb;
    VLC vlc;
    Node nodes[512];

    for(i = 0; i < 256; i++)
        nodes[i].count = bytestream_get_le32(&src);
    size -= 1024;
    if (ff_huff_build_tree(s->avctx, &vlc, 256, nodes, huff_cmp,
                           FF_HUFFMAN_FLAG_ZERO_COUNT) < 0)
        return -1;
    /* we have built Huffman table and are ready to decode plane */

    /* convert bits so they may be used by standard bitreader */
    s->dsp.bswap_buf((uint32_t *)s->tmpbuf, (const uint32_t *)src, size >> 2);

    init_get_bits(&gb, s->tmpbuf, size * 8);
    for(j = 0; j < h; j++){
        for(i = 0; i < w*step; i += step){
            dst[i] = get_vlc2(&gb, vlc.table, 9, 3);
            /* lines are stored as deltas between previous lines
             * and we need to add 0x80 to the first lines of chroma planes
             */
            if(j) dst[i] += dst[i - stride];
            else if(Uoff) dst[i] += 0x80;
            if (get_bits_left(&gb) < 0) {
                ff_free_vlc(&vlc);
                return AVERROR_INVALIDDATA;
            }
        }
        dst += stride;
    }
    ff_free_vlc(&vlc);
    return 0;
}

static void fraps_frame_copy(FrapsContext *s, uint8_t *dst_data[3], int dst_linesizes[3],
                             uint8_t *src_data[3], const int src_linesizes[3],
                             enum PixelFormat pix_fmt, int width, int height)
{
    const AVPixFmtDescriptor *desc = &av_pix_fmt_descriptors[pix_fmt];
    int i;

    for (i = 0; i < 3; i++) {
        int h = height;
        int bwidth = av_image_get_linesize(pix_fmt, width, i);
        if (i) {
            h = -((-height)>>desc->log2_chroma_h);
        }
        ff_thread_await_progress(&s->buf_ptrs[s->prev_index], i, 0);
        av_image_copy_plane(dst_data[i], dst_linesizes[i],
                            src_data[i], src_linesizes[i],
                            bwidth, h);
        ff_thread_report_progress(&s->buf_ptrs[s->cur_index], i, 0);
    }
}

static int decode_frame(AVCodecContext *avctx,
                        void *data, int *data_size,
                        AVPacket *avpkt)
{
    const uint8_t *buf = avpkt->data;
    int buf_size = avpkt->size;
    FrapsContext * const s = avctx->priv_data;
    AVFrame *frame = data;
    AVFrame *f;
    uint32_t header;
    unsigned int version,header_size;
    unsigned int x, y;
    const uint32_t *buf32;
    uint32_t *luma1,*luma2,*cb,*cr;
    uint32_t offs[4];
    int i, j, is_chroma, is_Pframe, ret;
    const int planes = 3;
    uint8_t *out;
    enum PixelFormat pix_fmt;

    header = AV_RL32(buf);
    version = header & 0xff;
    header_size = (header & (1<<30))? 8 : 4; /* bit 30 means pad to 8 bytes */

    if (version > 5) {
        av_log(avctx, AV_LOG_ERROR,
               "This file is encoded with Fraps version %d. " \
               "This codec can only decode versions <= 5.\n", version);
        return -1;
    }

    buf += header_size;

    if (version < 2) {
        unsigned needed_size = avctx->width*avctx->height*3;
        if (version == 0) {
            if ((avctx->width % 8) != 0 || (avctx->height % 2) != 0) {
                av_log(avctx, AV_LOG_ERROR, "Invalid frame size %dx%d\n",
                       avctx->width, avctx->height);
                return -1;
            }
            needed_size /= 2;
        }
        needed_size += header_size;
        if (buf_size != needed_size && buf_size != header_size) {
            av_log(avctx, AV_LOG_ERROR,
                   "Invalid frame length %d (should be %d)\n",
                   buf_size, needed_size);
            return -1;
        }
        /* bit 31 means same as previous pic */
        is_Pframe = (header & (1U<<31)) ? 1 : 0;
    } else {
        is_Pframe = buf_size == 8 ? 1 : 0;
        if (!is_Pframe) {
            if (AV_RL32(buf) != FPS_TAG || buf_size < (planes*1024 + 24)) {
                av_log(avctx, AV_LOG_ERROR, "Fraps: error in data stream\n");
                return -1;
             }
            for(i = 0; i < planes; i++) {
                offs[i] = AV_RL32(buf + 4 + i * 4);
                if(offs[i] >= buf_size - header_size || (i && offs[i] <= offs[i - 1] + 1024)) {
                    av_log(avctx, AV_LOG_ERROR, "Fraps: plane %i offset is out of bounds\n", i);
                    return -1;
                }
            }
            offs[planes] = buf_size - header_size;
            for(i = 0; i < planes; i++) {
                av_fast_padded_malloc(&s->tmpbuf, &s->tmpbuf_size, offs[i + 1] - offs[i] - 1024);
                if (!s->tmpbuf)
                    return AVERROR(ENOMEM);
            }
        }
    }

    if (is_Pframe && !s->buf_ptrs[s->prev_index].data[0]) {
        av_log(avctx, AV_LOG_ERROR, "decoding must start with keyframe\n");
        return -1;
    }

    f = &s->buf_ptrs[s->cur_index];
    if (f->data[0])
        ff_thread_release_buffer(avctx, f);

    pix_fmt = version & 1 ? PIX_FMT_BGR24 : PIX_FMT_YUVJ420P;
    if (avctx->pix_fmt != pix_fmt && is_Pframe) {
        av_log(avctx, AV_LOG_ERROR, "p-frame after pix_fmt change, dropped\n");
        return -1;
    }
    avctx->pix_fmt = pix_fmt;

    f->reference = 3;

    if (is_Pframe) {
        f->pict_type = AV_PICTURE_TYPE_P;
        f->key_frame = 0;
    } else {
        f->pict_type = AV_PICTURE_TYPE_I;
        f->key_frame = 1;
    }

    if ((ret = ff_thread_get_buffer(avctx, f)) < 0) {
        av_log(avctx, AV_LOG_ERROR, "get_buffer() failed\n");
        return ret;
    }

    s->next_prev_index = s->cur_index;
    s->next_cur_index  = (s->cur_index - 1) & 1;

    ff_thread_finish_setup(avctx);

    /* Copy previous frame */
    if (is_Pframe) {
        fraps_frame_copy(s, f->data, f->linesize, s->buf_ptrs[s->prev_index].data,
                         s->buf_ptrs[s->prev_index].linesize, avctx->pix_fmt, avctx->width, avctx->height);
        goto end;
    }

    switch(version) {
    case 0:
    default:
        buf32=(const uint32_t*)buf;
        for(y=0; y<avctx->height/2; y++){
            luma1=(uint32_t*)&f->data[0][ y*2*f->linesize[0] ];
            luma2=(uint32_t*)&f->data[0][ (y*2+1)*f->linesize[0] ];
            cr=(uint32_t*)&f->data[1][ y*f->linesize[1] ];
            cb=(uint32_t*)&f->data[2][ y*f->linesize[2] ];
            for(x=0; x<avctx->width; x+=8){
                *luma1++ = *buf32++;
                *luma1++ = *buf32++;
                *luma2++ = *buf32++;
                *luma2++ = *buf32++;
                *cr++    = *buf32++;
                *cb++    = *buf32++;
            }
        }
        ff_thread_report_progress(f, INT_MAX, 0);
        break;

    case 1:
        /* Fraps v1 is an upside-down BGR24 */
        for(y=0; y<avctx->height; y++)
            memcpy(&f->data[0][ (avctx->height-y)*f->linesize[0] ],
                   &buf[y*avctx->width*3],
                   3*avctx->width);
        ff_thread_report_progress(f, INT_MAX, 0);
        break;

    case 2:
    case 4:
        /**
         * Fraps v2 is Huffman-coded YUV420 planes
         * Fraps v4 is virtually the same
         */
        for(i = 0; i < planes; i++){
            is_chroma = !!i;
            if(fraps2_decode_plane(s, f->data[i], f->linesize[i], avctx->width >> is_chroma,
                    avctx->height >> is_chroma, buf + offs[i], offs[i + 1] - offs[i], is_chroma, 1) < 0) {
                av_log(avctx, AV_LOG_ERROR, "Error decoding plane %i\n", i);
                if (avctx->active_thread_type & FF_THREAD_FRAME) {
                    ff_thread_report_progress(f, INT_MAX, 0);
                    break;
                }
                else
                    return -1;
            } else
              ff_thread_report_progress(f, i, 0);
        }
        break;
    case 3:
    case 5:
        /* Virtually the same as version 4, but is for RGB24 */
        for(i = 0; i < planes; i++){
            if(fraps2_decode_plane(s, f->data[0] + i + (f->linesize[0] * (avctx->height - 1)), -f->linesize[0],
                    avctx->width, avctx->height, buf + offs[i], offs[i + 1] - offs[i], 0, 3) < 0) {
                av_log(avctx, AV_LOG_ERROR, "Error decoding plane %i\n", i);
                if (avctx->active_thread_type & FF_THREAD_FRAME)
                    break;
                else
                    return -1;
            }
        }
        out = f->data[0];
        // convert pseudo-YUV into real RGB
        for(j = 0; j < avctx->height; j++){
            uint8_t *line_end = out + 3*avctx->width;
            while (out < line_end) {
                out[0]  += out[1];
                out[2]  += out[1];
                out += 3;
            }
            out += f->linesize[0] - 3*avctx->width;
        }
        ff_thread_report_progress(f, INT_MAX, 0);
        break;
    }

end:
    *frame = *f;
    *data_size = sizeof(AVFrame);

    s->prev_index = s->next_prev_index;
    s->cur_index  = s->next_cur_index;

    /* Only release frames that aren't used anymore */
    if(s->buf_ptrs[s->cur_index].data[0])
        ff_thread_release_buffer(avctx, &s->buf_ptrs[s->cur_index]);

    return buf_size;
}


/**
 * closes decoder
 * @param avctx codec context
 * @return 0 on success or negative if fails
 */
static av_cold int decode_end(AVCodecContext *avctx)
{
    FrapsContext *s = (FrapsContext*)avctx->priv_data;
    int i;

    av_freep(&s->tmpbuf);

    if (avctx->internal->is_copy)
        return 0;

    for(i = 0; i < 2; i++)
        if(s->buf_ptrs[i].data[0])
            ff_thread_release_buffer(avctx, &s->buf_ptrs[i]);

    return 0;
}


AVCodec ff_fraps_decoder = {
    .name           = "fraps",
    .type           = AVMEDIA_TYPE_VIDEO,
    .id             = CODEC_ID_FRAPS,
    .priv_data_size = sizeof(FrapsContext),
    .init           = decode_init,
    .close          = decode_end,
    .decode         = decode_frame,
    .capabilities   = CODEC_CAP_DR1 | CODEC_CAP_FRAME_THREADS,
    .long_name      = NULL_IF_CONFIG_SMALL("Fraps"),
    .update_thread_context = ONLY_IF_THREADS_ENABLED(fraps_decode_update_thread_context)
};
