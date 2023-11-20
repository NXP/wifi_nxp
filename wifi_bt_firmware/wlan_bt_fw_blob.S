;/*
; * Copyright 2023 NXP
; *
; * All rights reserved.
; * 
; * SPDX-License-Identifier: BSD-3-Clause
; */

#include "app_config.h"

#if defined(__CC_ARM)

#if defined(SD8801)

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN 8801/sd8801_wlan.bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

#endif

#if defined(SD8978)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN IW416/sduartIW416_wlan_bt.bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

#else

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN IW416/sdIW416_wlan.bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT bt_fw_bin
        EXPORT bt_fw_bin_end
        EXOORT bt_fw_bin_len
bt_fw_bin
        INCBIN IW416/uartIW416_bt.bin
bt_fw_bin_end
bt_fw_bin_len
        INT bt_fw_bin_end - bt_fw_bin
        END

#endif
#endif

#if defined(SD8987)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN 8987/sduart8987_wlan_bt.bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT bt_fw_bin
        EXPORT bt_fw_bin_end
        EXOORT bt_fw_bin_len
bt_fw_bin
bt_fw_bin_end
bt_fw_bin_len
        INT bt_fw_bin_end - bt_fw_bin
        END

#else

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN 8987/sd8987_wlan.bin
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT bt_fw_bin
        EXPORT bt_fw_bin_end
        EXOORT bt_fw_bin_len
bt_fw_bin
        INCBIN 8987/uart8987_bt.bin
bt_fw_bin_end
bt_fw_bin_len
        INT bt_fw_bin_end - bt_fw_bin
        END

#endif
#endif

#if defined(SD9177)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN "nw61x/sduart_nw61x.bin.se"
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT bt_fw_bin
        EXPORT bt_fw_bin_end
        EXOORT bt_fw_bin_len
bt_fw_bin
bt_fw_bin_end
bt_fw_bin_len
        INT bt_fw_bin_end - bt_fw_bin
        END

#else

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT wlan_fw_bin
        EXPORT wlan_fw_bin_end
        EXOORT wlan_fw_bin_len
wlan_fw_bin
        INCBIN nw61x/sd_nw61x.bin.se
wlan_fw_bin_end
wlan_fw_bin_len
        INT wlan_fw_bin_end - wlan_fw_bin
        END

        AREA M0CODE, DATA, READONLY, PREINIT_ARRAY, ALIGN=3
        EXPORT bt_fw_bin
        EXPORT bt_fw_bin_end
        EXOORT bt_fw_bin_len
bt_fw_bin
        INCBIN nw61x/uart_nw61x.bin.se
bt_fw_bin_end
bt_fw_bin_len
        INT bt_fw_bin_end - bt_fw_bin
        END

#endif
#endif

#elif defined(__GNUC__) || defined(__ARMCC_VERSION)

#if defined(SD8801)

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "8801/sd8801_wlan.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

#endif

#if defined(SD8978)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "IW416/sduartIW416_wlan_bt.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#else

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "IW416/sdIW416_wlan.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .incbin "IW416/uartIW416_bt.bin"
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#endif
#endif

#if defined(SD8987)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "8987/sduart8987_wlan_bt.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#else

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "8987/sd8987_wlan.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .incbin "8987/uart8987_bt.bin"
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#endif
#endif

#if defined(SD9177)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "nw61x/sduart_nw61x.bin.se"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#else

        .section .m0code , "ax" @progbits @preinit_array
        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "nw61x/sd_nw61x.bin.se"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin
        .end

        .section .m0code , "ax" @progbits @preinit_array
        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .incbin "nw61x/uart_nw61x.bin.se"
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin
        .end

#endif
#endif

#endif
