LIBAVCODEC_$MAJOR {
        global: av*;
                #deprecated, remove after next bump
                audio_resample;
                audio_resample_close;
                #LAV usage
                ff_vc1_pixel_aspect;
                ff_crop_tab;
        local:  *;
};
