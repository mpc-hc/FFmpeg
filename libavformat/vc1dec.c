/*
 * RAW VC-1 video demuxer
 * Copyright (c) 2012 Hendrik Leppkes <h.leppkes@gmail.com>
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

#include "avformat.h"
#include "rawdec.h"

#include "libavcodec/vc1.h"

static int vc1_probe(AVProbeData *p)
{
    uint32_t code= -1;
    int frame=0,ep=0,seqhdr=0,res=0;
    int i;

    for(i=0; i<p->buf_size; i++){
        code = (code<<8) + p->buf[i];
        if (IS_MARKER(code)) {
            switch(code){
            case VC1_CODE_ENTRYPOINT:
              ep++;
              break;
            case VC1_CODE_SEQHDR:
              seqhdr++;
              break;
            case VC1_CODE_FRAME:
              frame++;
              break;
            case VC1_CODE_SLICE:
            case VC1_CODE_FIELD:
            case VC1_CODE_ENDOFSEQ:
              break;
            default:
              res++;
              if (code > 0x0000011F)
                return 0;
              break;
            }
        }
    }
    if(ep && seqhdr && frame && res<(frame+ep+seqhdr))
        return AVPROBE_SCORE_MAX/2+1;
    return 0;
}

FF_DEF_RAWVIDEO_DEMUXER(vc1, "raw VC-1", vc1_probe, "vc1", CODEC_ID_VC1)
