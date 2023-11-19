;/*
; * Copyright 2023 NXP
; *
; * All rights reserved.
; * 
; * SPDX-License-Identifier: BSD-3-Clause
; */

#if defined(SD8801)

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

#endif

#if defined(SD8978)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

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

#else

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

#endif
#endif

#if defined(SD8987)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

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

#else

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

#endif
#endif

#if defined(SD9177)
#if !defined(CONFIG_WIFI_IND_DNLD) && !defined(CONFIG_BT_IND_DNLD)

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

#else

        .global wlan_fw_bin
        .type wlan_fw_bin, %object
        .align 4
wlan_fw_bin:
        .incbin "nw61x/sd_nw61x_se.bin"
        .global wlan_fw_bin_end
        .type wlan_fw_bin_end, %object
wlan_fw_bin_end:
        .global wlan_fw_bin_len
        .type wlan_fw_bin_len, %object
        .align 4
wlan_fw_bin_len:
        .int  wlan_fw_bin_end - wlan_fw_bin

        .global bt_fw_bin
        .type bt_fw_bin, %object
        .align 4
bt_fw_bin:
        .incbin "nw61x/uart_nw61x_se.bin"
        .global bt_fw_bin_end
        .type bt_fw_bin_end, %object
bt_fw_bin_end:
        .global bt_fw_bin_len
        .type bt_fw_bin_len, %object
        .align 4
bt_fw_bin_len:
        .int  bt_fw_bin_end - bt_fw_bin

#endif
#endif
