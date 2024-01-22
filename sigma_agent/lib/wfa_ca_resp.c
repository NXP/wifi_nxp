/****************************************************************************
 Copyright (c) 2015 Wi-Fi Alliance
 Permission to use, copy, modify, and/or distribute this software for any
 purpose with or without fee is hereby granted, provided that the above
 copyright notice and this permission notice appear in all copies.
 THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER
 RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT,
 NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE
 USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/*
 *       File: wfa_ca_resp.c
 *       All functions are desginated to handle the command responses from
 *       a DUT and inform TM the command status.
 *       They will be called by Control Agent.
 *
 *       Revision History:
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
//#include <sys/socket.h>

#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_main.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_miscs.h"
#include "wfa_ca.h"
#include "wfa_rsp.h"
#include "wfa_sock.h"
#include "wfa_ca_resp.h"
#include "wfa_cmds.h"

extern unsigned short wfa_defined_debug;
char gRespStr[WFA_BUFF_512];

dutCommandRespFuncPtr wfaCmdRespProcFuncTbl[WFA_STA_RESPONSE_END + 1] = {
    caCmdNotDefinedYet, wfaGetVersionResp, /* WFA_GET_VERSION_RESP_TLV - WFA_STA_COMMANDS_END                  (1) */
    wfaTrafficAgentPingStartResp,          /* WFA_TRAFFIC_SEND_PING_RESP_TLV - WFA_STA_COMMANDS_END (2) */
    wfaTrafficAgentPingStopResp,           /* WFA_TRAFFIC_STOP_PING_RESP_TLV - WFA_STA_COMMANDS_END (3) */
    wfaTrafficAgentConfigResp,             /* WFA_TRAFFIC_AGENT_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END (4) */
    wfaTrafficAgentSendResp,               /* WFA_TRAFFIC_AGENT_SEND_RESP_TLV - WFA_STA_COMMANDS_END  (5) */
    wfaStaGenericResp,                     /* WFA_TRAFFIC_AGENT_RECV_START_RESP_TLV - WFA_STA_COMMANDS_END  (6) */
    wfaTrafficAgentRecvStopResp,           /* WFA_TRAFFIC_AGENT_RECV_STOP_RESP_TLV - WFA_STA_COMMANDS_END  (7) */
    wfaStaGenericResp,                     /* WFA_TRAFFIC_AGENT_RESET_RESP_TLV - WFA_STA_COMMANDS_END  (8) */
    caCmdNotDefinedYet,                    /* WFA_TRAFFIC_AGENT_STATUS_RESP_TLV - WFA_STA_COMMANDS_END  (9) */

    wfaStaGetIpConfigResp,     /* WFA_STA_GET_IP_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END   (10) */
    wfaStaGenericResp,         /* WFA_STA_SET_IP_CONFIG_RESP_TLV - WFA_STA_COMMANDS_END    (11) */
    wfaStaGetMacAddressResp,   /* WFA_STA_GET_MAC_ADDRESS_RESP_TLV - WFA_STA_COMMANDS_END    (12) */
    wfaStaGenericResp,         /* WFA_STA_SET_MAC_ADDRESS_RESP_TLV - WFA_STA_COMMANDS_END  (13) */
    wfaStaIsConnectedResp,     /* WFA_STA_IS_CONNECTED_RESP_TLV - WFA_STA_COMMANDS_END     (14) */
    wfaStaVerifyIpConnectResp, /* WFA_STA_VERIFY_IP_CONNECTION_RESP_TLV - WFA_STA_COMMANDS_END    (15) */
    wfaStaGetBSSIDResp,        /* WFA_STA_GET_BSSID_RESP_TLV - WFA_STA_COMMANDS_END     (16) */
    wfaStaGetStatsResp,        /* WFA_STA_GET_STATS_RESP_TLV - WFA_STA_COMMANDS_END   (17) */
    wfaStaSetEncryptionResp,   /* WFA_STA_SET_ENCRYPTION_RESP_TLV - WFA_STA_COMMANDS_END   (18) */
    wfaStaGenericResp,         /* WFA_STA_SET_PSK_RESP_TLV - WFA_STA_COMMANDS_END     (19) */
    wfaStaGenericResp,         /* WFA_STA_SET_EAPTLS_RESP_TLV - WFA_STA_COMMANDS_END   (20) */
    wfaStaGenericResp,         /* WFA_STA_SET_UAPSD_RESP_TLV - WFA_STA_COMMANDS_END     (21) */
    wfaStaGenericResp,         /* WFA_STA_ASSOCIATE_RESP_TLV - WFA_STA_COMMANDS_END   (22) */
    wfaStaGenericResp,         /* WFA_STA_SET_EAPTTLS_RESP_TLV - WFA_STA_COMMANDS_END   (23) */
    wfaStaGenericResp,         /* WFA_STA_SET_EAPSIM_RESP_TLV - WFA_STA_COMMANDS_END   (24) */
    wfaStaGenericResp,         /* WFA_STA_SET_PEAP_RESP_TLV - WFA_STA_COMMANDS_END    (25) */
    wfaStaGenericResp,         /* WFA_STA_SET_IBSS_RESP_TLV - WFA_STA_COMMANDS_END    (26) */
    wfaStaGetInfoResp,         /* WFA_STA_GET_INFO_RESP_TLV - WFA_STA_COMMANDS_END         (27) */
    wfaDeviceGetInfoResp,      /* WFA_DEVICE_GET_INFO_RESP_TLV - WFA_STA_COMMANDS_END     (28) */
    wfaDeviceListIFResp,       /* WFA_DEVICE_LIST_IF_RESP_TLV - WFA_STA_COMMANDS_END   (29) */
    wfaStaGenericResp,         /* WFA_STA_DEBUG_SET_RESP_TLV - WFA_STA_COMMANDS_END    (30) */
    wfaStaGenericResp,         /* WFA_STA_SET_MODE_RESP_TLV - WFA_STA_COMMANDS_END    (31) */
    wfaStaUploadResp,          /* WFA_STA_UPLOAD_RESP_TLV - WFA_STA_COMMANDS_END     (32) */
    wfaStaGenericResp,         /* WFA_STA_SET_WMM_RESP_TLV - WFA_STA_COMMANDS_END     (33) */
    wfaStaGenericResp,         /* WFA_STA_REASSOCIATE_RESP_TLV - WFA_STA_COMMANDS_END  (34) */
    wfaStaGenericResp,         /* WFA_STA_SET_PWRSAVE_RESP_TLV - WFA_STA_CMMANDS_END    (35) */
    wfaStaGenericResp,         /* WFA_STA_SET_POWER_SAVE_RESP_TLV - WFA_STA_CMMANDS_END    (36) */
    wfaStaGenericResp,         /* WFA_STA_SEND_NEIGREQ_RESP_TLV - WFA_STA_COMMANDS_END  (37) */
    wfaStaGenericResp,         /* WFA_STA_PRESET_PARAMETERS_RESP_TLV-WFA_STA_COMMANDS_END (38) */
    wfaStaGenericResp,         /* WFA_STA_SET_EAPFAST_RESP_TLV -WFA_STA_COMMANDS_END  (39)*/
    wfaStaGenericResp,         /* WFA_STA_SET_EAPAKA_RESP_TLV-WFA_STA_COMMANDS_END  (40)*/
    wfaStaGenericResp,         /* WFA_STA_SET_SYSTIME_RESP_TLV-WFA_STA_COMMANDS_END  (41)*/
    wfaStaGenericResp,         /* WFA_STA_SET_11N_RESP_TLV-WFA_STA_COMMANDS_END  (42)*/
    wfaStaGenericResp,         /* WFA_STA_SET_WIRELESS_RESP_TLV-WFA_STA_COMMANDS_END  (43)*/
    wfaStaGenericResp,         /* WFA_STA_SEND_AADBA_RESP_TLV-WFA_STA_COMMANDS_END  (44)*/
    wfaStaGenericResp,         /* WFA_STA_SET_COEXIST_MGMT_RESP_TLV-WFA_STA_COMMANDS_END  (45)*/
    wfaStaGenericResp,         /* WFA_STA_SET_RIFS_TEST_RESP_TLV-WFA_STA_COMMANDS_END  (46)*/
    wfaStaGenericResp,         /* WFA_STA_RESET_DEFAULT_RESP_TLV-WFA_STA_COMMANDS_END  (47)*/
    wfaStaGenericResp,         /* WFA_STA_DISCONNECT_RESP_TLV-WFA_STA_COMMANDS_END  (48)*/
    wfaStaGenericResp,         /* WFA_STA_DEV_SEND_FRAME_RESP_TLV-WFA_STA_COMMANDS_END  (49)*/
    wfaStaGenericResp,         /* WFA_STA_SET_SECURITY_RESP_TLV-WFA_STA_COMMANDS_END   (50)*/

    /* P2P */
    wfaStaGetP2pDevAddressResp, /* ( (WFA_STA_GET_P2P_DEV_ADDRESS_RESP_TLV-WFA_STA_COMMANDS_END  - (51)*/
    wfaStaGenericResp,          /* (WFA_STA_SET_P2P_RESP_TLV -WFA_STA_COMMANDS_END (52) */
    wfaStaGenericResp,          /* (WFA_STA_SET_P2P_CONNECT_RESP_TLV -WFA_STA_COMMANDS_END (53)  */
    wfaStaStartAutoGO,          /* (WFA_STA_START_AUTO_GO_RESP_TLV -WFA_STA_COMMANDS_END (54) */
    wfaStaP2pStartGrpFormResp,  /* (WFA_STA_P2P_START_GRP_FORMATION_RESP_TLV-WFA_STA_COMMANDS_END - (55) */

    wfaStaGenericResp, /* (WFA_STA_P2P_DISSOLVE_RESP_TLV -  (56)*/
    wfaStaGenericResp, /* (WFA_STA_SEND_P2P_INV_REQ_RESP_TLV - (57) */
    wfaStaGenericResp, /* (WFA_STA_ACCEPT_P2P_INV_REQ_RESP_TLV -(58)  */
    wfaStaGenericResp, /* (WFA_STA_SEND_P2P_PROV_DIS_REQ_RESP_TLV-  (59)*/

    wfaStaGenericResp, /* (WFA_STA_SET_WPSPBC_RESP_TLV -  (60)*/

    wfaStaWpsReadPinResp, /* (WFA_STA_WPS_READ_PIN_RESP_TLV - (61) */
    wfaStaGenericResp,    /* (WFA_STA_WPS_ENTER_PIN_RESP_TLV -  (62)*/
    wfaStaGetPskResp,     /* (WFA_STA_GET_PSK_RESP_TLV -  (63)*/
    wfaStaGenericResp,    /* (WFA_STA_P2P_RESET_RESP_TLV -  (64)*/

    wfaStaWpsReadLabelResp,   /* (WFA_STA_WPS_READ_LABEL_RESP_TLV -(65)  */
    wfaStaGetP2pIpConfigResp, /* WFA_STA_GET_P2P_IP_CONFIG_RESP_TLV  - (66) */
    wfaStaGenericResp,        /* WFA_STA_SEND_SERVICE_DISCOVERY_REQ_RESP_TLV (67) */
    wfaStaGenericResp,        /* (WFA_STA_SEND_P2P_PRESENCE_REQ_RESP_TLV -(68)  */
    wfaStaGenericResp,        /* WFA_STA_SET_SLEEP_REQ_RESP_TLV (69)*/
    wfaStaGenericResp,        /* WFA_STA_P2P_SET_OPPORTUNISTIC_PS_TLV (70) */

    wfaStaGenericResp,            /* WFA_STA_ADD_ARP_TABLE_ENTRY_RESP_TLV (71)  */
    wfaStaGenericResp,            /* WFA_STA_P2P_BLOCK_ICMP_RESPONSE_RESP_TLV(72) */
                                  /* P2P */
    wfaStaGenericResp,            /* WFA_STA_SET_RADIO_RESP_TLV(73) */
    wfaStaGenericResp,            /* WFA_STA_SET_RFEATURE_RESP_TLS (74)*/
    wfaStaStartWfdConnectionResp, /* WFA_STA_START_WFD_CONNECTION_RESP_TLS (75)*/
    wfaStaCliCmdResp,             /* WFA_STA_CLI_CMD_RESP_TLV (76) */
    wfaStaConnectGoStartWfdResp,  /*WFA_STA_CONNECT_GO_START_WFD_RESP_TLV (77) */
    wfaStaGenericResp,            /* WFA_STA_GENERATE_EVENT_RESP_TLV (78) */
    wfaStaGenericResp,            /* 79 */
    wfaStaGetParameterResp,       /* WFA_STA_GET_PARAMETER_RESP_TLV (80) */

    wfaStaGenericResp,      /* WFA_AP_SET_WIRELESS_RESP_TLV (81) */
    wfaStaGenericResp,      /* WFA_AP_SET_SECURITY_RESP_TLV (82) */
    wfaStaGenericResp,      /* WFA_AP_SET_REBOOT_RESP_TLV (83) */
    wfaAPConfigCommitResp,  /* WFA_AP_CONFIG_COMMIT_RESP_TLV (84) */
    wfaStaGenericResp,      /* WFA_AP_SET_11n_RESP_TLV (85) */
    wfaStaGenericResp,      /*WFA_AP_RESET_DEFAULT_RESP_TLV (86) */
    wfaStaGenericResp,      /*WFA_AP_SET_STA_QOS _RESP_TLV (87) */
    wfaStaGenericResp,      /* WFA_AP_SET_QOS _RESP_TLV (88) */
    wfaStaGenericResp,      /*WFA_AP_SEND_ADDBA _RESP_TLV (89) */
    wfaStaGenericResp,      /*WFA_AP_SET_RFEATURE_RESP_TLV (90) */
    wfaStaGenericResp,      /*WFA_AP_SET_RADIUS _RESP_TLV (91) */
    wfaStaGenericResp,      /*WFA_AP_SET_11D _RESP_TLV (92) */
    wfaStaGenericResp,      /* WFA_AP_SET_11N_WIRELESS_RESP_TLV (93)*/
    wfaStaGenericResp,      /* WFA_AP_SET_PMF_RESP_TLV (94) */
    wfaApGetMacAddressResp, /*WFA_AP_GET_MACADDRESS_RESP_TLV (95) */
    wfaStaGenericResp,      /* WFA_AP_DEAUTH_STA_RESP_TLV (96) */

    wfaStaGenericResp,      /*WFA_STA_BSSID_POOL_RESP_TLV  (97) */
    wfaStaGenericResp,      /* WFA_STA_ADD_CREDENTIAL_RESP_TLV (98) */
    wfaStaHS2AssocResp,     /*WFA_STA_HS2_ASSOCIATE_RESP_TLV  (99) */
    wfaStaScanResp,         /* WFA_STA_SCAN_RESP_TLV  (100) */
    wfaStaGenericResp,      /* WFA_STA_HS2_DEV_SET_PARAMETER_RESP_TLV (101) */
    wfaStaGenericResp,      /*WFA_STA_OSU_RESP_TLV  (102) */
    wfaStaGenericResp,      /* WFA_STA_RESET_PARAM_RESP_TLV (103) */
    wfaStaPolicyUpdateResp, /* WFA_STA_POLICY_UPDATE_RESP_TLV (104) */
    wfaStaGenericResp,      /* WFA_STA_EXEC_ACTION_RESP_TLV (105) */
    wfaStaGenericResp,      /* WFA_STA_DEV_CONFIGURE_IE_RESP_TLV (106) */
    wfaStaGenericResp,      /*WFA_AP_SET_11H _RESP_TLV (107) */
    wfaStaGenericResp,      /* WFA_STA_RESPONSE_END-RESP_TLV (108) */
    wfaStaGenericResp,      /* WFA_AP_DEV_EXEC_ACTION_RESP_TLV (109) */
};

extern int gSock, gCaSockfd;

int caCmdNotDefinedYet(BYTE *cmdBuf)
{
    int done;

    sprintf(gRespStr, "status,ERROR,Command Not Defined\r\n");
    /* make sure if getting send error, will close the socket */
    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    done = 0;

    return done;
}

int wfaStaVerifyIpConnectResp(BYTE *cmdBuf)
{
    int done                     = 0;
    dutCmdResponse_t *verifyResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaVerifyIpConnectResp\n");
    switch (verifyResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaVerifyConnect running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,connected,%i\r\n", verifyResp->cmdru.connected);
            DPRINT_INFO(WFA_OUT, "%s", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            DPRINT_INFO(WFA_OUT, "%s", gRespStr);

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }
    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaIsConnectedResp(BYTE *cmdBuf)
{
    int done                        = 0;
    dutCmdResponse_t *connectedResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaIsConnectedResp ...\n");
    switch (connectedResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaIsConnectd running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,connected,%i\r\n", connectedResp->cmdru.connected);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            break;
        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaStaGetIpConfigResp(BYTE *cmdBuf)
{
    int done                          = 0;
    dutCmdResponse_t *getIpConfigResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetIpConfigResp ...\n");
    switch (getIpConfigResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetIpConfig running ...\n");
            done = 1;
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            break;

        case STATUS_COMPLETE:
            if (strlen(getIpConfigResp->cmdru.getIfconfig.dns[0]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[0] = '\0';
            if (strlen(getIpConfigResp->cmdru.getIfconfig.dns[1]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[1] = '\0';

            if (getIpConfigResp->cmdru.getIfconfig.ipv6addr[0] != '\0')
            {
                sprintf(gRespStr, "status,COMPLETE,ip,%s\r\n", getIpConfigResp->cmdru.getIfconfig.ipv6addr);
                break;
            }

            sprintf(gRespStr, "status,COMPLETE,dhcp,%i,ip,%s,mask,%s,primary-dns,%s,secondary-dns,%s\r\n",
                    getIpConfigResp->cmdru.getIfconfig.isDhcp, getIpConfigResp->cmdru.getIfconfig.ipaddr,
                    getIpConfigResp->cmdru.getIfconfig.mask, getIpConfigResp->cmdru.getIfconfig.dns[0],
                    getIpConfigResp->cmdru.getIfconfig.dns[1]);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaGetVersionResp(BYTE *cmdBuf)
{
    int done                     = 0;
    dutCmdResponse_t *getverResp = (dutCmdResponse_t *)(cmdBuf + 4);

    switch (getverResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaGetVersion running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,version,%s\r\n", getverResp->cmdru.version);
            break;
        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaStaGetInfoResp(BYTE *cmdBuf)
{
    dutCmdResponse_t *infoResp = (dutCmdResponse_t *)(cmdBuf + 4);
    int done                   = 0;

    switch (infoResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetInfo running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,%s\r\n", infoResp->cmdru.info);
            DPRINT_INFO(WFA_OUT, "info: %s\n", infoResp->cmdru.info);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaTrafficAgentConfigResp(BYTE *cmdBuf)
{
    int done                        = 0;
    dutCmdResponse_t *agtConfigResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentConfigResp ...\n");
    switch (agtConfigResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaTrafficAgentConfig running ...\n");
            done = 1;
            break;
        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,streamID,%i\r\n", agtConfigResp->streamId);
            break;
        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaTrafficAgentSendResp(BYTE *cmdBuf)
{
    int done = 1, i;
    char copyBuf[64];
    int errorStatus = 0;
    wfaTLV *ptlv    = (wfaTLV *)cmdBuf;
    int len         = ptlv->len;
    int numStreams;
    dutCmdResponse_t *statResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentSendResp ...\n");

    numStreams = (len / sizeof(dutCmdResponse_t));
    printf("total %i streams\n", numStreams);
    for (i = 0; i < numStreams; i++)
    {
        if (statResp->status != STATUS_COMPLETE)
        {
            errorStatus = 1;
        }
    }

    if (errorStatus)
    {
        sprintf(gRespStr, "status,ERROR");
    }
    else
    {
        sprintf(gRespStr, "status,COMPLETE,streamID,");
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %i", statResp[i].streamId);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }

        printf("streamids %s\n", gRespStr);

        strncat(gRespStr, ",txFrames,", 10);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.txFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }

        strncat(gRespStr, ",rxFrames,", 10);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.rxFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }

        strncat(gRespStr, ",txPayloadBytes,", 16);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, "%llu ", statResp[i].cmdru.stats.txPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }

        strncat(gRespStr, ",rxPayloadBytes,", 16);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %llu ", statResp[i].cmdru.stats.rxPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",outOfSequenceFrames,", 20);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, "%i ", statResp[i].cmdru.stats.outOfSequenceFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }

        printf("jitter %lu\n", statResp[i].cmdru.stats.jitter);
        strncat(gRespStr, "\r\n", 4);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaTrafficAgentRecvStopResp(BYTE *cmdBuf)
{
    int done        = 1;
    int i           = 0;
    int errorStatus = 0;
    char copyBuf[64];
    BYTE *dutRsp   = cmdBuf + 4;
    BYTE *startRsp = dutRsp;
    wfaTLV *ptlv   = (wfaTLV *)cmdBuf;
    int len        = ptlv->len;
    int numStreams = len / sizeof(dutCmdResponse_t);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentRecvStopResp ...\n");

    dutCmdResponse_t statResp[WFA_MAX_TRAFFIC_STREAMS];
    for (i = 0; i < numStreams; i++)
    {
        dutRsp = startRsp + i * sizeof(dutCmdResponse_t);
        memcpy(&statResp[i], dutRsp, sizeof(dutCmdResponse_t));
    }
    for (i = 0; i < numStreams; i++)
    {
        if (statResp[i].status != STATUS_COMPLETE)
            errorStatus = 1;
    }
    if (errorStatus)
    {
        sprintf(gRespStr, "status,ERROR");
    }
    else
    {
        sprintf(gRespStr, "status,COMPLETE,streamID,");
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %d", statResp[i].streamId);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",txFrames,", 10);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %u", statResp[i].cmdru.stats.txFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",rxFrames,", 10);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %u", statResp[i].cmdru.stats.rxFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",txPayloadBytes,", 16);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %llu", statResp[i].cmdru.stats.txPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",rxPayloadBytes,", 16);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %llu", statResp[i].cmdru.stats.rxPayloadBytes);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, ",outOfSequenceFrames,", 20);
        for (i = 0; i < numStreams; i++)
        {
            sprintf(copyBuf, " %d", statResp[i].cmdru.stats.outOfSequenceFrames);
            strncat(gRespStr, copyBuf, sizeof(copyBuf) - 1);
        }
        strncat(gRespStr, "\r\n", 4);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    printf("gRespStr = %s", gRespStr);
    return done;
}

int wfaTrafficAgentPingStartResp(BYTE *cmdBuf)
{
    int done                      = 0;
    dutCmdResponse_t *staPingResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaTrafficAgentPingStartResp ...\n");

    switch (staPingResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaTrafficAgentPingStart running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,streamID,%i\r\n", staPingResp->streamId);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);

    return done;
}

int wfaTrafficAgentPingStopResp(BYTE *cmdBuf)
{
    int done                  = 0;
    dutCmdResponse_t *stpResp = (dutCmdResponse_t *)(cmdBuf + 4);

    switch (stpResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaTrafficAgentPingStop running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
        {
            sprintf(gRespStr, "status,COMPLETE,sent,%d,replies,%d\r\n", stpResp->cmdru.pingStp.sendCnt,
                    stpResp->cmdru.pingStp.repliedCnt);
            DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
            break;
        }

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

int wfaStaGetMacAddressResp(BYTE *cmdBuf)
{
    int done                     = 0;
    dutCmdResponse_t *getmacResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetMacAddressResp ...\n");
    switch (getmacResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetMacAddress running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,mac,%s\r\n", getmacResp->cmdru.mac);
            printf("status,COMPLETE,mac,%s\r\n", getmacResp->cmdru.mac);
            break;

        case STATUS_ERROR:
            printf("status,ERROR\n");
            sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
            break;

        default:
            sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
            printf("unknown status\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaGetBSSIDResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *getBssidResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetMacAddressResp ...\n");
    switch (getBssidResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetBSSID running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,bssid,%s\r\n", getBssidResp->cmdru.bssid);
            printf("status,COMPLETE,bssid,%s\r\n", getBssidResp->cmdru.bssid);
            break;
        case STATUS_ERROR:
            printf("status,ERROR\n");
            sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
            break;
        default:
            sprintf(gRespStr, "status,COMPLETE,mac,00:00:00:00:00:00\r\n");
            printf("unknown status\n");
    }
    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaSetEncryptionResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *getBssidResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetBSSIDResp ...\n");
    switch (getBssidResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaSetEncryption running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            // sprintf(gRespStr, "status,COMPLETE,bssid,%s\r\n", getBssidResp->cmdru.bssid);
            sprintf(gRespStr, "status,COMPLETE\r\n");
            printf("status,COMPLETE,bssid,%s\r\n", getBssidResp->cmdru.bssid);
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            printf("status,ERROR\r\n");
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaGetStatsResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *getStatsResp = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaGetStatsResp_t *stats     = &getStatsResp->cmdru.ifStats;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetStatsResp ...\n");

    switch (getStatsResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetStats running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(
                gRespStr,
                "status,COMPLETE,txFrames,%i,rxFrames,%i,txMulticast,%i,rxMulticast,%i,fcsErrors,%i,txRetries,%i\r\n",
                stats->txFrames, stats->rxFrames, stats->txMulticast, stats->rxMulticast, stats->fcsErrors,
                stats->txRetries);
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaDeviceGetInfoResp(BYTE *cmdBuf)
{
    int done                      = 1;
    dutCmdResponse_t *devInfoResp = (dutCmdResponse_t *)(cmdBuf + 4);
    caDeviceGetInfoResp_t *dinfo  = &devInfoResp->cmdru.devInfo;

    switch (devInfoResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaDeviceGetInfo running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            if (dinfo->firmware[0] != '\0' || dinfo->firmware[0] != '\n')
                // sprintf(gRespStr, "status,COMPLETE,firmware,%s\r\n", dinfo->firmware);
                sprintf(gRespStr, "status,COMPLETE,vendor,%s,model,%s,version,%s\r\n", dinfo->vendor, dinfo->model,
                        dinfo->version);
            else
                sprintf(gRespStr, "status,COMPLETE,vendor,%s,model,%s,version,%s\r\n", dinfo->vendor, dinfo->model,
                        dinfo->version);
            DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaDeviceListIFResp(BYTE *cmdBuf)
{
    int done                        = 0, i;
    dutCmdResponse_t *devListIfResp = (dutCmdResponse_t *)(cmdBuf + 4);
    caDeviceListIFResp_t *ifResp    = &devListIfResp->cmdru.ifList;

    switch (devListIfResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaDeviceListIF running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            if (ifResp->iftype == IF_80211)
            {
                sprintf(gRespStr, "status,COMPLETE,interfaceType,802.11,interfaceID");
                DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
                DPRINT_INFO(WFA_OUT, "%s\n", ifResp->ifs[0]);
            }
            else if (ifResp->iftype == IF_ETH)
                sprintf(gRespStr, "status,COMPLETE,interfaceType,Ethernet,interfaceID");

            for (i = 0; i < 1; i++)
            {
                if (ifResp->ifs[i][0] != '\0')
                {
                    strncat(gRespStr, ",", 4);
                    strncat(gRespStr, ifResp->ifs[i], sizeof(ifResp->ifs[i]));
                    strncat(gRespStr, "\r\n", 4);
                }
            }

            DPRINT_INFO(WFA_OUT, "%s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaUploadResp(BYTE *cmdBuf)
{
    int done                     = 0;
    dutCmdResponse_t *uploadResp = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaUploadResp_t *upld      = &uploadResp->cmdru.uld;

    switch (uploadResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaUpload running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,code,%i,%s\r\n", upld->seqnum, upld->bytes);
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            printf("status,COMPLETE\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaGetP2pDevAddressResp(BYTE *cmdBuf)
{
    int done                        = 0;
    dutCmdResponse_t *p2pDevAddResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetP2pDevAddressResp ...\n");

    printf("Inside response function...");
    printf("Inside response function...");
    printf("Inside response function...");
    printf("Inside response function...");
    printf("Inside response function...");

    switch (p2pDevAddResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetP2pDevAddressResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,devid,%s\r\n", p2pDevAddResp->cmdru.devid);
            printf("status,COMPLETE,devid,%s\r\n", p2pDevAddResp->cmdru.devid);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaStartAutoGO(BYTE *cmdBuf)
{
    int done                  = 0;
    dutCmdResponse_t *p2pResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaStartAutoGO ...\n");
    switch (p2pResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaStartAutoGO running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,groupid,%s\r\n", p2pResp->cmdru.grpid);
            printf("status,COMPLETE,groupid,%s\r\n", p2pResp->cmdru.grpid);
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaP2pStartGrpFormResp(BYTE *cmdBuf)
{
    int done                         = 0;
    dutCmdResponse_t *p2pResp        = (dutCmdResponse_t *)(cmdBuf + 4);
    caP2pStartGrpFormResp_t *grpInfo = &p2pResp->cmdru.grpFormInfo;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaP2pStartGrpFormResp ...\n");
    switch (p2pResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaP2pStartGrpFormResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,result,%s,groupid,%s\r\n", grpInfo->result, grpInfo->grpId);
            printf("status,COMPLETE,result,%s,groupid,%s\r\n", grpInfo->result, grpInfo->grpId);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaWpsReadPinResp(BYTE *cmdBuf)
{
    int done                  = 0;
    dutCmdResponse_t *p2pResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaWpsReadPinResp ...\n");
    switch (p2pResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaWpsReadPinResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,pin,%s\r\n", p2pResp->cmdru.wpsPin);
            printf("status,COMPLETE,pin,%s\r\n", p2pResp->cmdru.wpsPin);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaGetPskResp(BYTE *cmdBuf)
{
    int done                      = 0;
    dutCmdResponse_t *p2pResp     = (dutCmdResponse_t *)(cmdBuf + 4);
    caP2pStaGetPskResp_t *pskInfo = &p2pResp->cmdru.pskInfo;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetPskResp ...\n");
    switch (p2pResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetPskResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,passphrase,%s,ssid,%s\r\n", pskInfo->passPhrase, pskInfo->ssid);
            printf("status,COMPLETE,passphrase,%s,ssid,%s\r\n", pskInfo->passPhrase, pskInfo->ssid);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaWpsReadLabelResp(BYTE *cmdBuf)
{
    int done                  = 0;
    dutCmdResponse_t *p2pResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaWpsReadLabelResp ...\n");
    switch (p2pResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaWpsReadLabelResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,label,%s\r\n", p2pResp->cmdru.wpsPin);
            printf("status,COMPLETE,label,%s\r\n", p2pResp->cmdru.wpsPin);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaGetP2pIpConfigResp(BYTE *cmdBuf)
{
    int done                          = 0;
    dutCmdResponse_t *getIpConfigResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetP2pIpConfigResp ...\n");
    switch (getIpConfigResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetP2pIpConfigResp running ...\n");
            done = 1;
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            break;

        case STATUS_COMPLETE:
            if (strlen(getIpConfigResp->cmdru.getIfconfig.dns[0]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[0] = '\0';
            if (strlen(getIpConfigResp->cmdru.getIfconfig.dns[1]) == 0)
                *getIpConfigResp->cmdru.getIfconfig.dns[1] = '\0';

            sprintf(gRespStr, "status,COMPLETE,dhcp,%i,ip,%s,mask,%s,primary-dns,%s,p2pinterfaceaddress,%s\r\n",
                    getIpConfigResp->cmdru.getIfconfig.isDhcp, getIpConfigResp->cmdru.getIfconfig.ipaddr,
                    getIpConfigResp->cmdru.getIfconfig.mask, getIpConfigResp->cmdru.getIfconfig.dns[0],
                    getIpConfigResp->cmdru.getIfconfig.mac);

            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
int wfaStaGenericResp(BYTE *cmdBuf)
{
    int done                     = 0;
    dutCmdResponse_t *setwmmResp = (dutCmdResponse_t *)(cmdBuf + 4);

    switch (setwmmResp->status)
    {
        case STATUS_RUNNING:
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE\r\n");
            printf("status,COMPLETE\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            printf("status,COMPLETE\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaStartWfdConnectionResp(BYTE *cmdBuf)
{
    int done                             = 0;
    dutCmdResponse_t *wfdResp            = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaStartWfdConnResp_t *wfdConnInfo = &wfdResp->cmdru.wfdConnInfo;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaStartWfdConnectionResp ...\n");
    switch (wfdResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaStartWfdConnectionResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,result,%s,groupid,%s,wfdsessionid,%s\r\n", wfdConnInfo->result,
                    wfdConnInfo->p2pGrpId, wfdConnInfo->wfdSessionId);
            printf("status,COMPLETE,result,%s,groupid,%s,wfdsessionid,%s\r\n", wfdConnInfo->result,
                   wfdConnInfo->p2pGrpId, wfdConnInfo->wfdSessionId);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaCliCmdResp(BYTE *cmdBuf)
{
    int done                         = 0;
    caStaCliCmdResp_t *staCliCmdResp = (caStaCliCmdResp_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaStaCliCmdResp ...\n");
    switch (staCliCmdResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaCliCmdResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            if (staCliCmdResp->resFlag == 1)
            {
                sprintf(gRespStr, "status,COMPLETE,%s\r\n", staCliCmdResp->result);
                printf("\nstatus,COMPLETE,%s****\r\n", staCliCmdResp->result);
            }
            else
            {
                sprintf(gRespStr, "status,COMPLETE\r\n");
                printf("status,COMPLETE\r\n");
            }

            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            printf("status,ERROR\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaConnectGoStartWfdResp(BYTE *cmdBuf)
{
    int done                             = 0;
    dutCmdResponse_t *wfdResp            = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaStartWfdConnResp_t *wfdConnInfo = &wfdResp->cmdru.wfdConnInfo;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaConnectGoStartWfdResp ...\n");
    switch (wfdResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaConnectGoStartWfdResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,wfdsessionid,%s\r\n", wfdConnInfo->wfdSessionId);
            printf("status,COMPLETE,wfdsessionid,%s\r\n", wfdConnInfo->wfdSessionId);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaGetParameterResp(BYTE *cmdBuf)
{
    int done = 0;
    int ret;
    dutCmdResponse_t *wfdResp             = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaGetParameterResp_t *getParamInfo = &wfdResp->cmdru.getParamValue;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaGetParameterResp ...\n");
    switch (wfdResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaGetParameterResp running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            //	printf("\n the value of  getparaminfo-> paramtype is %d",getParamInfo->getParamType);
            if (getParamInfo->getParamType == eDiscoveredDevList)
            {
                sprintf(gRespStr, "status,COMPLETE,DeviceList,%s\r\n", getParamInfo->devList);
                printf("status,COMPLETE,DeviceList,%s\r\n", getParamInfo->devList);
                break;
            }
            else if (getParamInfo->getParamType == eRSSI)
            {
                sprintf(gRespStr, "status,COMPLETE,rssi,%d\r\n", getParamInfo->rssi_resp);
                printf("status,COMPLETE,rssi,%d\r\n", getParamInfo->rssi_resp);
                break;
            }
            else if (getParamInfo->getParamType == ePMK)
            {
                sprintf(gRespStr, "status,COMPLETE,pmk,%s\r\n", getParamInfo->pmk_resp);
                printf("status,COMPLETE,pmk,%s\r\n", getParamInfo->pmk_resp);
                break;
            }

            else
            {
                printf("\n the value of  getparaminfo-> paramtype is %d", getParamInfo->getParamType);
                sprintf(gRespStr, "status,COMPLETE,rssi,%s\r\n", getParamInfo->rssi_resp);
                printf("status,COMPLETE,rssi,%s\r\n", getParamInfo->rssi_resp);
                break;
            }

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

// DD: MBSSID SANRESULTS-RETURN-START
int wfaStaScanResp(BYTE *cmdBuf)
{
    int done = 0;
    int ret;
    dutCmdResponse_t *wfdResp         = (dutCmdResponse_t *)(cmdBuf + 4);
    caStaMBSSSCANResp_t *getParamInfo = &wfdResp->cmdru.getMBSS_SCAN_RES;

    DPRINT_INFO(WFA_OUT, "Entering wfaStaScanResp ...\n");
    switch (wfdResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaStaScanResp  running ...\n");
            done = 1;
            break;

        case STATUS_COMPLETE:
            if (getParamInfo->mbss_scan_flag == eMBSS_SCANS)
            {
                printf("\n\rThe OP is \n\r-----------------%s\r\n-----------------", getParamInfo->mbss_scan_res_resp);
                sprintf(gRespStr, "status,COMPLETE,%s\r\n", getParamInfo->mbss_scan_res_resp);
                printf("status,COMPLETE,%s\r\n", getParamInfo->mbss_scan_res_resp);
                break;
            }
            else
            {
                sprintf(gRespStr, "status,COMPLETE\r\n");
                printf("status,COMPLETE\r\n");

                break;
            }

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

// DD: MBSSID SCAN RESULTS END

#ifdef EXPERIMENTAL_AP_SUPPORT
int wfaAPConfigCommitResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *apCommitResp = (dutCmdResponse_t *)(cmdBuf + 4);

    switch (apCommitResp->status)
    {
        case STATUS_RUNNING:
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE\r\n");
            printf("status,COMPLETE\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            sprintf(gRespStr, "status,ERROR\r\n");
            printf("status,COMPLETE\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_INVALID:
            sprintf(gRespStr, "status,INVALID,reason,%s\r\n", apCommitResp->cmdru.reason);
            printf("status,INVALID,reason,%s\r\n", apCommitResp->cmdru.reason);
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        default:
            sprintf(gRespStr, "status,INVALID\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaApGetMacAddressResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *apGetMacResp = (dutCmdResponse_t *)(cmdBuf + 4);

    DPRINT_INFO(WFA_OUT, "Entering wfaApGetMacAddressResp ...\n");
    switch (apGetMacResp->status)
    {
        case STATUS_RUNNING:
            DPRINT_INFO(WFA_OUT, "wfaApGetMacAddress running ...\n");
            done = 1;
            break;
        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,mac,%s\r\n", apGetMacResp->cmdru.apMacAddrInfo.mac);
            break;
        default:
            sprintf(gRespStr, "status,INVALID\r\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));
    return done;
}

#endif

int wfaStaHS2AssocResp(BYTE *cmdBuf)
{
    int done                       = 0;
    dutCmdResponse_t *staAssocResp = (dutCmdResponse_t *)(cmdBuf + 4);
    DPRINT_INFO(WFA_OUT, "Entering wfaStaHS2AssocResp ...\n");

    switch (staAssocResp->status)
    {
        case STATUS_RUNNING:
            sprintf(gRespStr, "status,RUNNING\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,SSID,%s,BSSID,%s\r\n", staAssocResp->cmdru.assocInfo.SSID,
                    staAssocResp->cmdru.assocInfo.BSSID);
            break;

        case STATUS_ERROR:
            printf("status,ERROR\n");
            sprintf(gRespStr, "status,ERROR\r\n");
            break;

        default:
            sprintf(gRespStr, "status,COMPLETE\r\n");
            printf("unknown status\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}

int wfaStaPolicyUpdateResp(BYTE *cmdBuf)
{
    int done                              = 0;
    dutCmdResponse_t *staPolicyUpdateResp = (dutCmdResponse_t *)(cmdBuf + 4);
    DPRINT_INFO(WFA_OUT, "Entering wfaStaPolicyUpdateResp ...\n");

    switch (staPolicyUpdateResp->status)
    {
        case STATUS_RUNNING:
            sprintf(gRespStr, "status,RUNNING\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            done = 1;
            break;

        case STATUS_COMPLETE:
            sprintf(gRespStr, "status,COMPLETE,PolicyUpdateStatus,SUCCESS\r\n");
            DPRINT_INFO(WFA_OUT, " %s\n", gRespStr);
            break;

        case STATUS_ERROR:
            printf("status,ERROR\n");
            sprintf(gRespStr, "status,ERROR\r\n");
            break;

        default:
            sprintf(gRespStr, "status,COMPLETE,PolicyUpdateStatus,FAIL\r\n");
            printf("unknown status\n");
    }

    wfaCtrlSend(gCaSockfd, (BYTE *)gRespStr, strlen(gRespStr));

    return done;
}
