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
 *      File: wfa_cmdproc.c
 *      Library functions to handle all string command parsing and convert it
 *      to an internal format for DUT. They should be called by Control Agent
 *      and Test console while receiving commands from CLI or TM
 *
 *      Revision History:
 *        2006/03/10  -- initially created by qhu
 *        2006/06/01    -- BETA release by qhu
 *        2006/06/13    -- 00.02 release by qhu
 *        2006/06/30    -- 00.10 Release by qhu
 *        2006/07/10  -- 01.00 Release by qhu
 *        2006/08/30  -- add some print statements by Isaac in Epson.
 *        2006/09/01  -- 01.05 release by qhu
 *        2006/10/26    -- 01.06 release by qhu
 *        2006/12/02    -- bug fix reported by p.schwan
 *        2007/01/11    -- 01.10 release by qhu
 *        2007/02/15  -- WMM Extension Beta released by qhu, mkaroshi
 *        2007/03/30  -- 01.40 WPA2 and Official WMM Beta Release by qhu
 *        2007/04/20  -- 02.00 WPA2 and Official WMM Release by qhu
 *        2007/08/15 --  02.10 WMM-Power Save release by qhu
 *        2007/10/10 --  02.20 Voice SOHO beta -- qhu
 *        2007/11/07 --  02.30 Voice HSO -- qhu
 *        2007/12/10 --  02.32 Add a funtion to upload test results.
 *        2008/01/03 --  02.34 Support the result upload command.
 *        2008/02/11 --  02.40 Fix the BUG 5, multiple issues.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "wfa_debug.h"
#include "wfa_types.h"
#include "wfa_tlv.h"
#include "wfa_tg.h"
#include "wfa_ca.h"
#include "wfa_cmds.h"
#include "wfa_rsp.h"
#include "wfa_miscs.h"
#include "wfa_agtctrl.h"
#include "nxp_macros.h"
#include "nxp_gvars.h"
int BAND_24G = 0;
int BAND_5G  = 0;
int HE525    = 0;
int HE527    = 0;
extern int gSock;
extern void printProfile(tgProfile_t *);
int wfaStandardBoolParsing(char *str);

/* command KEY WORD String table */
typeNameStr_t keywordStr[] = {
    {KW_PROFILE, "profile", NULL},
    {KW_DIRECTION, "direction", NULL},
    {KW_DIPADDR, "destination", NULL},
    {KW_DPORT, "destinationport", NULL},
    {KW_SIPADDR, "source", NULL},
    {KW_SPORT, "sourceport", NULL},
    {KW_FRATE, "framerate", NULL},
    {KW_DURATION, "duration", NULL},
    {KW_PLOAD, "payloadsize", NULL},
    {KW_TCLASS, "trafficClass", NULL}, /* It is to indicate WMM traffic pattern */
    {KW_STREAMID, "streamid", NULL},
    {KW_STARTDELAY, "startdelay", NULL}, /* It is used to schedule multi-stream test such as WMM */
    {KW_NUMFRAME, "numframes", NULL},
    {KW_USESYNCCLOCK, "useSyncClock", NULL},
    {KW_USERPRIORITY, "userpriority", NULL},
    {KW_MAXCNT, "maxcnt", NULL},
    {KW_TAGNAME, "tagName", NULL},
    {KW_HTI, "hti", NULL},
};

/* profile type string table */
typeNameStr_t profileStr[] = {
    {PROF_FILE_TX, "file_transfer", NULL},
    {PROF_MCAST, "multicast", NULL},
    {PROF_IPTV, "iptv", NULL},          /* This is used for WMM, confused? */
    {PROF_TRANSC, "transaction", NULL}, /* keep for temporary backward compat., will be removed */
    {PROF_START_SYNC, "start_sync", NULL},
    {PROF_CALI_RTD, "cali_rtd", NULL},
    {PROF_UAPSD, "uapsd", NULL}};

/* direction string table */
typeNameStr_t direcStr[] = {{DIRECT_SEND, "send", NULL}, {DIRECT_RECV, "receive", NULL}};
char iface_for_policy_update[WFA_IF_NAME_LEN];
/*
 * cmdProcNotDefinedYet(): a dummy function
 */
int cmdProcNotDefinedYet(char *pcmdStr, char *buf, int *len)
{
    printf("The command processing function not defined.\n");

    /* need to send back a response */

    return (WFA_SUCCESS);
}

extern unsigned short wfa_defined_debug;
int is_valid_runtime_config_param(char *header, char *key)
{
    char temp[256];
    int ret;
    read_ini_config(SIGMA_USER_CONFIG, "Debug", "runtime_config_mode", temp);
    ret = atoi(temp);
    if (!ret)
        return ret;
    read_ini_config(SIGMA_USER_CONFIG, header, key, temp);
    if (temp[0] == '\0')
    {
        ret = 0;
    }
    else
    {
        ret = 1;
    }
    return ret;
}
int read_ini_config(char *fileName, char *header, char *label, char *value)
{
    char *str;
    FILE *tmpfd;
    char string[255];
    char *saveptr;
    char header_filter[256];
    tmpfd = fopen(fileName, "r");
    if (tmpfd == NULL)
    {
        printf("File open failed\n%d", __LINE__);
        return FALSE;
    }
    value[0] = '\0';
    sprintf(header_filter, "[%s]", header);
    for (;;)
    {
        if (fgets(string, 256, tmpfd) == NULL)
            break;
        if (strncmp(string, header_filter, strlen(header_filter)) == 0)
        {
            for (;;)
            {
                if (fgets(string, 256, tmpfd) == NULL)
                    break;
                if (strstr(string, "[") && strstr(string, "]"))
                    break;
                if (strncmp(string, label, strlen(label)) == 0)
                {
                    str = strtok_r(string, "=", &saveptr);
                    if (str != NULL)
                        strcpy(value, saveptr);
                    else
                        strcpy(value, "");
                    if (value[strlen(value) - 1] == '\n')
                    {
                        value[strlen(value) - 1] = '\0';
                    }
                    break;
                }
            }
        }
    }
    fclose(tmpfd);
    return TRUE;
}

/*
 *  xcCmdProcGetVersion(): process the command get_version string from TM
 *                         to convert it into a internal format
 *  input:        pcmdStr -- a string pointer to the command string
 */
int xcCmdProcGetVersion(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    DPRINT_INFO(WFA_OUT, "start xcCmdProcGetVersion ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    /* encode the tag without values */
    wfaEncodeTLV(WFA_GET_VERSION_TLV, 0, NULL, aBuf);

    *aLen = 4;

    return WFA_SUCCESS;
}

/*
 *  xcCmdProcAgentConfig(): process the command traffic_agent_config string
 *                          from TM to convert it into a internal format
 *  input:        pcmdStr -- a string pointer to the command string
 */
int xcCmdProcAgentConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    int i = 0, j = 0, kwcnt = 0;
    wfaTLV *hdr      = (wfaTLV *)aBuf;
    tgProfile_t tgpf = {0, 0, "", -1, "", -1, 0, 0, 0, TG_WMM_AC_BE, 0, 0};
    tgProfile_t *pf  = &tgpf;
    int userPrio     = 0;

    DPRINT_INFO(WFA_OUT, "start xcCmdProcAgentConfig ...\n");
    DPRINT_INFO(WFA_OUT, "params:  %s\n", pcmdStr);

    if (aBuf == NULL)
        return WFA_FAILURE;

    while ((str = strtok_r(NULL, ",", (char **)&pcmdStr)) != NULL)
    {
        for (i = 0; i < sizeof(keywordStr) / sizeof(typeNameStr_t); i++)
        {
            if (strcasecmp(str, keywordStr[i].name) == 0)
            {
                switch (keywordStr[i].type)
                {
                    case KW_PROFILE:
                        str = strtok_r(NULL, ",", (char **)&pcmdStr);
                        if (isString(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect profile keyword format\n");
                            return WFA_FAILURE;
                        }

                        for (j = 0; j < PROF_LAST; j++)
                        {
                            if (strcasecmp(str, profileStr[j].name) == 0)
                            {
                                pf->profile = profileStr[j].type;
                            }
                        }

                        DPRINT_INFO(WFA_OUT, "profile type %i\n", pf->profile);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_DIRECTION:
                        str = strtok_r(NULL, ",", (char **)&pcmdStr);
                        if (isString(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect direction keyword format\n");
                            return WFA_FAILURE;
                        }

                        if (strcasecmp(str, "send") == 0)
                        {
                            pf->direction = DIRECT_SEND;
                        }
                        else if (strcasecmp(str, "receive") == 0)
                        {
                            pf->direction = DIRECT_RECV;
                        }
                        else
                            printf("Don't know direction\n");

                        DPRINT_INFO(WFA_OUT, "direction %i\n", pf->direction);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_DIPADDR: /* dest ip address */
                        memcpy(pf->dipaddr, strtok_r(NULL, ",", &pcmdStr), IPV4_ADDRESS_STRING_LEN);
                        if (isIpV4Addr(pf->dipaddr) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect ipaddr format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "dipaddr %s\n", pf->dipaddr);

                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_DPORT:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect port number format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "dport %s\n", str);
                        pf->dport = atoi(str);

                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_SIPADDR:
                        memcpy(pf->sipaddr, strtok_r(NULL, ",", &pcmdStr), IPV4_ADDRESS_STRING_LEN);

                        if (isIpV4Addr(pf->sipaddr) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect ipaddr format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "sipaddr %s\n", pf->sipaddr);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_SPORT:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect port number format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "sport %s\n", str);
                        pf->sport = atoi(str);

                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_FRATE:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect frame rate format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "framerate %s\n", str);
                        pf->rate = atoi(str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_DURATION:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect duration format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "duration %s\n", str);
                        pf->duration = atoi(str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_PLOAD:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect payload format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "payload %s\n", str);
                        pf->pksize = atoi(str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_STARTDELAY:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect startDelay format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "startDelay %s\n", str);
                        pf->startdelay = atoi(str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_MAXCNT:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect max count format\n");
                            return WFA_FAILURE;
                        }
                        pf->maxcnt = atoi(str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_TAGNAME:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pf->WmmpsTagName, str, strlen(str));
                        printf("Got name %s\n", pf->WmmpsTagName);
                        break;

                    case KW_HTI:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "on") == 0)
                            pf->hti = WFA_ON;
                        else
                            pf->hti = WFA_OFF;

                        str = NULL;
                        break;

                    case KW_TCLASS:
                        str = strtok_r(NULL, ",", &pcmdStr);

                        // if user priority is used, tclass is ignored.
                        if (userPrio == 1)
                            break;

                        if (strcasecmp(str, "voice") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_VO;
                        }
                        else if (strcasecmp(str, "Video") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_VI;
                        }
                        else if (strcasecmp(str, "Background") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_BK;
                        }
                        else if (strcasecmp(str, "BestEffort") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_BE;
                        }
                        else
                        {
                            pf->trafficClass = TG_WMM_AC_BE;
                        }

                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_USERPRIORITY:
                        str = strtok_r(NULL, ",", &pcmdStr);

                        if (strcasecmp(str, "6") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP6;
                        }
                        else if (strcasecmp(str, "7") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP7;
                        }
                        else if (strcasecmp(str, "5") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP5;
                        }
                        else if (strcasecmp(str, "4") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP4;
                        }
                        else if (strcasecmp(str, "1") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP1;
                        }
                        else if (strcasecmp(str, "2") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP2;
                        }
                        else if (strcasecmp(str, "0") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP0;
                        }
                        else if (strcasecmp(str, "3") == 0)
                        {
                            pf->trafficClass = TG_WMM_AC_UP3;
                        }

                        // if User Priority is used
                        userPrio = 1;

                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_STREAMID:
                        kwcnt++;
                        break;

                    case KW_NUMFRAME:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect numframe format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "num frame %s\n", str);
                        kwcnt++;
                        str = NULL;
                        break;

                    case KW_USESYNCCLOCK:
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (isNumber(str) == WFA_FAILURE)
                        {
                            DPRINT_ERR(WFA_ERR, "Incorrect sync clock format\n");
                            return WFA_FAILURE;
                        }
                        DPRINT_INFO(WFA_OUT, "sync clock %s\n", str);
                        kwcnt++;
                        str = NULL;
                        break;

                    default:;
                } /* switch */

                if (str == NULL)
                    break;
            } /* if */
        }     /* for */
    }         /* while */

#if 0
    if(kwcnt < 8)
    {
       printf("Incorrect command, missing parameters\n");
       return WFA_FAILURE;
    }
#endif

    printProfile(pf);
    hdr->tag = WFA_TRAFFIC_AGENT_CONFIG_TLV;
    hdr->len = sizeof(tgProfile_t);

    memcpy(aBuf + 4, pf, sizeof(tgpf));

    *aLen = 4 + sizeof(tgProfile_t);

    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentSend(): Process and send the Control command
 *                       "traffic_agent_send"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentSend(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, 512);

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentSend ...\n");
    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    /* take the stream ids */
    if (strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    /*
     * To handle there are multiple stream ids such as WMM
     */
    while (1)
    {
        sid = strtok_r(NULL, " ", &pcmdStr);
        if (sid == NULL)
            break;

        printf("sid %s\n", sid);
        if (isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        printf("id %i\n", strid);
        id_cnt++;

        memcpy(aBuf + 4 * id_cnt, (char *)&strid, 4);
    }

    hdr->tag = WFA_TRAFFIC_AGENT_SEND_TLV;
    hdr->len = 4 * id_cnt; /* multiple 4s if more streams */

    *aLen = 4 + 4 * id_cnt;

#if 1
    {
        int i;
        for (i = 0; i < *aLen; i++)
            printf("%x ", aBuf[i]);

        printf("\n");
    }
#endif

    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentReset(): Process and send the Control command
 *                       "traffic_agent_reset"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentReset(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentReset ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    hdr->tag = WFA_TRAFFIC_AGENT_RESET_TLV;
    hdr->len = 0; /* multiple 4s if more streams */

    *aLen = 4;

    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentRecvStart(): Process and send the Control command
 *                       "traffic_agent_receive_start"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentRecvStart(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentRecvStart ...%s\n", pcmdStr);

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if (str == NULL || str[0] == '\0')
    {
        DPRINT_ERR(WFA_ERR, "Null string\n");
        return WFA_FAILURE;
    }

    if (strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    while (1)
    {
        sid = strtok_r(NULL, " ", &pcmdStr);
        if (sid == NULL)
            break;

        if (isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        id_cnt++;

        memcpy(aBuf + 4 * id_cnt, (char *)&strid, 4);
    }

    hdr->tag = WFA_TRAFFIC_AGENT_RECV_START_TLV;
    hdr->len = 4 * id_cnt; /* multiple 4s if more streams */

    *aLen = 4 + 4 * id_cnt;

#if 1
    {
        int i;
        for (i = 0; i < *aLen; i++)
            printf("%x ", aBuf[i]);

        printf("\n");
    }
#endif
    return WFA_SUCCESS;
}

/*
 * xcCmdProcAgentRecvStop(): Process and send the Control command
 *                       "traffic_agent_receive_stop"
 * input - pcmdStr  parameter string pointer
 * return - WFA_SUCCESS or WFA_FAILURE;
 */
int xcCmdProcAgentRecvStop(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str, *sid;
    int strid;
    int id_cnt = 0;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcAgentRecvStop ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    /* there is only one stream for baseline. Will support
     * multiple streams later.
     */
    str = strtok_r(NULL, ",", &pcmdStr);

    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "streamid") != 0)
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }
    while (1)
    {
        sid = strtok_r(NULL, " ", &pcmdStr);
        if (sid == NULL)
            break;

        if (isNumber(sid) == WFA_FAILURE)
            continue;

        strid = atoi(sid);
        id_cnt++;

        memcpy(aBuf + 4 * id_cnt, (char *)&strid, 4);
    }

    hdr->tag = WFA_TRAFFIC_AGENT_RECV_STOP_TLV;
    hdr->len = 4 * id_cnt; /* multiple 4s if more streams */

    *aLen = 4 + 4 * id_cnt;

    return WFA_SUCCESS;
}

int xcCmdProcAgentSendPing(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr            = (wfaTLV *)aBuf;
    tgPingStart_t *staping = (tgPingStart_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    staping->type = 0;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "destination") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staping->dipaddr, str, WFA_IP_V6_ADDR_STR_LEN - 1);
            DPRINT_INFO(WFA_OUT, "destination %s\n", staping->dipaddr);
        }
        if (strcasecmp(str, "frameSize") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            staping->frameSize = atoi(str);
            DPRINT_INFO(WFA_OUT, "framesize %i\n", staping->frameSize);
        }
        if (strcasecmp(str, "frameRate") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            staping->frameRate = atoi(str);
            DPRINT_INFO(WFA_OUT, "framerate %i\n", staping->frameRate);
        }
        if (strcasecmp(str, "duration") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            staping->duration = atoi(str);
            DPRINT_INFO(WFA_OUT, "duration %i\n", staping->duration);
        }
        if (strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "udp") == 0)
                staping->type = 1;
            else
                staping->type = 0;
        }
        if (strcasecmp(str, "iptype") == 0)
        {
            str             = strtok_r(NULL, ",", &pcmdStr);
            staping->iptype = atoi(str);
            DPRINT_INFO(WFA_OUT, "ping iptype %i\n", staping->iptype);
        }
        if (strcasecmp(str, "DSCP") == 0)
        {
            printf("find DSCP value\n");
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("DSCP value is %s\n", str);
            staping->dscp = atoi(str);
            DPRINT_INFO(WFA_OUT, "dscp %i\n", staping->dscp);
        }
        if (strcasecmp(str, "qos") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "vo") == 0)
            {
                staping->qos = TG_WMM_AC_VO;
            }
            else if (strcasecmp(str, "vi") == 0)
            {
                staping->qos = TG_WMM_AC_VI;
            }
            else if (strcasecmp(str, "be") == 0)
            {
                staping->qos = TG_WMM_AC_BE;
            }
            else if (strcasecmp(str, "bk") == 0)
            {
                staping->qos = TG_WMM_AC_BK;
            }
            else
            {
                staping->qos = TG_WMM_AC_BE;
            }
        }
    }

    hdr->tag = WFA_TRAFFIC_SEND_PING_TLV;
    hdr->len = sizeof(tgPingStart_t);
    *aLen    = hdr->len + 4;
    return WFA_SUCCESS;
}

int xcCmdProcAgentStopPing(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr = (wfaTLV *)aBuf;
    char *str;
    int strid;
    str = strtok_r(NULL, ",", &pcmdStr);

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "streamid") == 0)
        str = strtok_r(NULL, ",", &pcmdStr);
    else
    {
        DPRINT_ERR(WFA_ERR, "invalid type name\n");
        return WFA_FAILURE;
    }

    if (isNumber(str) == WFA_FAILURE)
        return WFA_FAILURE;

    strid = atoi(str);

    memcpy(aBuf + 4, (char *)&strid, 4);

    hdr->tag = WFA_TRAFFIC_STOP_PING_TLV;
    hdr->len = 4; /* multiple 4s if more streams */

    *aLen = 8;

    return WFA_SUCCESS;
}

int xcCmdProcStaGetIpConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t getipconf;
    caStaSetIpConfig_t *ipconfig = (caStaSetIpConfig_t *)&getipconf.cmdsu.ipconfig;
    memset(&getipconf, 0, sizeof(dutCommand_t));
    ipconfig->type = 1; // default is ipv4

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetIpConfig ...\n");
    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(getipconf.intf, str, 15);
        }
        if (strcasecmp(str, "type") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            ipconfig->type = atoi(str);
            DPRINT_INFO(WFA_OUT, "get ip : ip type is  %s\n", ((ipconfig->type == 2) ? "ipv6" : "ipv4"));
        }
    }
    wfaEncodeTLV(WFA_STA_GET_IP_CONFIG_TLV, sizeof(dutCommand_t), (BYTE *)&getipconf, aBuf);
    *aLen = 4 + sizeof(getipconf);
    return WFA_SUCCESS;
}

int xcCmdProcStaSetIpConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t staSetIpConfig;
    caStaSetIpConfig_t *setip    = (caStaSetIpConfig_t *)&staSetIpConfig.cmdsu.ipconfig;
    caStaSetIpConfig_t defparams = {"", 0, "", "", "", "", ""};
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(setip, &defparams, sizeof(caStaSetIpConfig_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setip->intf);
        }
        else if (strcasecmp(str, "dhcp") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            setip->isDhcp = atoi(str);
            DPRINT_INFO(WFA_OUT, "dhcp %i\n", setip->isDhcp);
        }
        else if (strcasecmp(str, "ip") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->ipaddr, str, 15);
            DPRINT_INFO(WFA_OUT, "ip %s\n", setip->ipaddr);
        }
        else if (strcasecmp(str, "mask") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->mask, str, 15);
            DPRINT_INFO(WFA_OUT, "mask %s\n", setip->mask);
        }
        else if (strcasecmp(str, "defaultGateway") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->defGateway, str, 15);
            DPRINT_INFO(WFA_OUT, "gw %s\n", setip->defGateway);
        }
        else if (strcasecmp(str, "primary-dns") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->pri_dns, str, 15);
            DPRINT_INFO(WFA_OUT, "dns p %s\n", setip->pri_dns);
        }
        else if (strcasecmp(str, "secondary-dns") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setip->sec_dns, str, 15);
            DPRINT_INFO(WFA_OUT, "dns s %s\n", setip->sec_dns);
        }
        else if (strcasecmp(str, "type") == 0)
        {
            str         = strtok_r(NULL, ",", &pcmdStr);
            setip->type = atoi(str);
            DPRINT_INFO(WFA_OUT, "get ip : ip type is  %s\n", ((setip->type == 2) ? "ipv6" : "ipv4"));
        }
        else
        {
            DPRINT_ERR(WFA_ERR, "invalid command %s\n", str);
            return WFA_FAILURE;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_IP_CONFIG_TLV, sizeof(staSetIpConfig), (BYTE *)&staSetIpConfig, aBuf);

    *aLen = 4 + sizeof(staSetIpConfig);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t getmac;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetMacAddress ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    memset(&getmac, 0, sizeof(getmac));
    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL)
        return WFA_FAILURE;

    slen = strlen(str);
    memcpy(getmac.intf, str, slen);
    wfaEncodeTLV(WFA_STA_GET_MAC_ADDRESS_TLV, sizeof(getmac), (BYTE *)&getmac, aBuf);

    *aLen = 4 + sizeof(getmac);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t setmac;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaSetMacAddress ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmac.intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setmac.intf);
        }
        else if (strcasecmp(str, "mac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmac.cmdsu.macaddr, str, 17);
            DPRINT_INFO(WFA_OUT, "mac %s\n", setmac.cmdsu.macaddr);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_MAC_ADDRESS_TLV, sizeof(setmac), (BYTE *)&setmac, aBuf);

    *aLen = 4 + sizeof(setmac);

    return WFA_SUCCESS;
}

int xcCmdProcStaIsConnected(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int slen;
    char *str = NULL;
    dutCommand_t isconnected;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaIsConnected\n");

    memset(&isconnected, 0, sizeof(isconnected));

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL)
        return WFA_FAILURE;

    slen = strlen(str);
    memcpy(isconnected.intf, str, slen);
    wfaEncodeTLV(WFA_STA_IS_CONNECTED_TLV, sizeof(isconnected), (BYTE *)&isconnected, aBuf);

    *aLen = 4 + sizeof(isconnected);

    return WFA_SUCCESS;
}

int xcCmdProcStaVerifyIpConnection(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    wfaTLV *hdr            = (wfaTLV *)aBuf;
    dutCommand_t *verifyip = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaVerifyIpConnection ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(verifyip->intf, str);
            verifyip->intf[15] = '\0';
            DPRINT_INFO(WFA_OUT, "interface %s %i\n", verifyip->intf, strlen(verifyip->intf));
        }
        else if (strcasecmp(str, "destination") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(verifyip->cmdsu.verifyIp.dipaddr, str, 15);
            DPRINT_INFO(WFA_OUT, "ip %s\n", verifyip->cmdsu.verifyIp.dipaddr);
        }
        else if (strcasecmp(str, "timeout") == 0)
        {
            str                              = strtok_r(NULL, ",", &pcmdStr);
            verifyip->cmdsu.verifyIp.timeout = atoi(str);
            DPRINT_INFO(WFA_OUT, "timeout %i\n", verifyip->cmdsu.verifyIp.timeout);
        }
    }

    wfaEncodeTLV(WFA_STA_VERIFY_IP_CONNECTION_TLV, sizeof(verifyip), (BYTE *)&verifyip, aBuf);

    hdr->tag = WFA_STA_VERIFY_IP_CONNECTION_TLV;
    hdr->len = sizeof(dutCommand_t);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetBSSID(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t getbssid;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetBSSID ...\n");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    memset(&getbssid, 0, sizeof(getbssid));
    str = strtok_r(NULL, ",", &pcmdStr);
    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL)
        return WFA_FAILURE;

    memcpy(getbssid.intf, str, WFA_IF_NAME_LEN - 1);
    getbssid.intf[WFA_IF_NAME_LEN - 1] = '\0';
    wfaEncodeTLV(WFA_STA_GET_BSSID_TLV, sizeof(getbssid), (BYTE *)&getbssid, aBuf);

    *aLen = 4 + sizeof(getbssid);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetStats(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t getstats;

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaGetStats ...\n");
    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    memset(&getstats, 0, sizeof(getstats));
    str = strtok_r(NULL, ",", &pcmdStr);
    /* need to check if the parameter name is called interface */
    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL)
        return WFA_FAILURE;

    memcpy(getstats.intf, str, WFA_IF_NAME_LEN - 1);
    getstats.intf[WFA_IF_NAME_LEN - 1] = '\0';
    wfaEncodeTLV(WFA_STA_GET_STATS_TLV, sizeof(getstats), (BYTE *)&getstats, aBuf);

    *aLen = 4 + sizeof(getstats);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetEncryption(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEncryption_t *setencryp = (caStaSetEncryption_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetEncryption_t defparams = {"", "", 0, {"", "", "", ""}, 0};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setencryp, (void *)&defparams, sizeof(caStaSetEncryption_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->ssid, str, 64);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "wep") == 0)
                setencryp->encpType = ENCRYPT_WEP;
            else
                setencryp->encpType = 0;
        }
        else if (strcasecmp(str, "key1") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[0], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[0]);
            setencryp->activeKeyIdx = 0;
        }
        else if (strcasecmp(str, "key2") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[1], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[1]);
        }
        else if (strcasecmp(str, "key3") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[2], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[2]);
        }
        else if (strcasecmp(str, "key4") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->keys[3], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setencryp->keys[3]);
        }
        else if (strcasecmp(str, "activeKey") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            setencryp->activeKeyIdx = atoi(str);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
        }
    }

    wfaEncodeTLV(WFA_STA_SET_ENCRYPTION_TLV, sizeof(caStaSetEncryption_t), (BYTE *)setencryp, aBuf);

    *aLen = 4 + sizeof(caStaSetEncryption_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    int ret                  = WFA_SUCCESS;
    dutCommand_t *cmd        = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    caStaSetSecurity_t *ssec = &cmd->cmdsu.setsec;
    char *str;
    int secType = 0;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(cmd->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ssec->ssid, str, 64);
            // DPRINT_INFO(WFA_OUT, "ssid %s\n", ssec->ssid);
            // DD-START
            if (strstr(ssec->ssid, "HE") != NULL)
            {
                if (strstr(ssec->ssid, "24G") != NULL)
                {
                    BAND_24G = 1;
                    BAND_5G  = 0;
                }
                else
                {
                    BAND_24G = 0;
                    BAND_5G  = 1;
                }
            }
            // DD-END
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "tkip") == 0 || strcasecmp(str, "aes-ccmp") == 0)
                strncpy(ssec->encpType, str, 9);
        }
        else if (strcasecmp(str, "KeyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "passphrase") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ssec->secu.passphrase, str, 64);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            ssec->pmf_flag = 1;
            if (strcasecmp(str, "optional") == 0)
                ssec->pmf = WFA_OPTIONAL;
            else if (strcasecmp(str, "required") == 0)
                ssec->pmf = WFA_REQUIRED;
            else
                ssec->pmf = WFA_DISABLED;
        }

        else if (strcasecmp(str, "type") == 0)
        {
            /* process the specific type of security */
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "psk") == 0)
            {
                ssec->type = secType = SEC_TYPE_PSK;
            }

            else if (strcasecmp(str, "eaptls") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPTLS;
            }
            else if (strcasecmp(str, "eapttls") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPTTLS;
            }
            else if (strcasecmp(str, "eappeap") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPPEAP;
            }
            else if (strcasecmp(str, "eapsim") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPSIM;
            }
            else if (strcasecmp(str, "eapfast") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPFAST;
            }
            else if (strcasecmp(str, "eapaka") == 0)
            {
                ssec->type = secType = SEC_TYPE_EAPAKA;
            }
            else if (strcasecmp(str, "sae") == 0)
            {
                ssec->type = secType = SEC_TYPE_SAE;
                ssec->SAE_FLAG       = 1;
            }
            else if (strcasecmp(str, "psk-sae") == 0)
            {
                ssec->type = secType = SEC_TYPE_SAE_PSK;
                ssec->SAE_FLAG       = 1;
            }
            else if (strcasecmp(str, "owe") == 0)
            {
                ssec->type = secType = SEC_TYPE_OWE;
            }
            else if (strcasecmp(str, "open") == 0)
            {
                ssec->type = secType = SEC_TYPE_OPEN;
            }
        }
        else if (strcasecmp(str, "passphrase") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ssec->secu.passphrase, str, 64);
        }
        else if (strcasecmp(str, "ECGroupID") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            ssec->groups_flag = 1;
            strcpy(ssec->groups, str);
        }
        else if (strcasecmp(str, "InvalidSAEElement") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            ssec->sae_invalid_element_flag = 1;
            strcpy(ssec->sae_invalid_element, str);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.username, str);
            DPRINT_INFO(WFA_OUT, "username %s\n", ssec->secu.ttls.username);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.passwd, str);
            DPRINT_INFO(WFA_OUT, "passwd %s\n", ssec->secu.ttls.passwd);
        }
        else if (strcasecmp(str, "trustedrootca") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.trustedRootCA, str);
            DPRINT_INFO(WFA_OUT, "trustedRootCA %s\n", ssec->secu.ttls.trustedRootCA);
        }
        else if (strcasecmp(str, "akmsuitetype") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ssec->secu.ttls.akmsuitetype = atoi(str);
            DPRINT_INFO(WFA_OUT, "akm %d\n", ssec->secu.ttls.akmsuitetype);
        }
        else if (strcasecmp(str, "pmksacaching") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ssec->secu.ttls.pmksacaching = atoi(str);
            DPRINT_INFO(WFA_OUT, "pmksacaching %d\n", ssec->secu.ttls.pmksacaching);
        }
        else if (strcasecmp(str, "clientCertificate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.client_cert, str);
            DPRINT_INFO(WFA_OUT, "client cert and private key  %s\n", ssec->secu.ttls.client_cert);
        }
        else if (strcasecmp(str, "ServerCert") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.server_cert, str);
            DPRINT_INFO(WFA_OUT, "server cert is  %s\n", ssec->secu.ttls.server_cert);
        }
        else if (strcasecmp(str, "TLSCipher") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.tls_cipher, str);
            ssec->secu.ttls.tls_cipher_flag = 1;
            DPRINT_INFO(WFA_OUT, "tls_cipher %s\n", ssec->secu.ttls.tls_cipher);
        }
        else if (strcasecmp(str, "CertType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.cert_type, str);
            DPRINT_INFO(WFA_OUT, "cert_type %s\n", ssec->secu.ttls.cert_type);
        }
        else if (strcasecmp(str, "pairwisecipher") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.pairwise_cipher, str);
            DPRINT_INFO(WFA_OUT, "pairwise_cipher %s\n", ssec->secu.ttls.pairwise_cipher);
        }
        else if (strcasecmp(str, "groupcipher") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.group_cipher, str);
            DPRINT_INFO(WFA_OUT, "group_cipher %s\n", ssec->secu.ttls.group_cipher);
        }
        else if (strcasecmp(str, "groupmgntcipher") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ssec->secu.ttls.group_mgmt_cipher, str);
            DPRINT_INFO(WFA_OUT, "group_mgmt_cipher %s\n", ssec->secu.ttls.group_mgmt_cipher);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_SECURITY_TLV, sizeof(caStaSetSecurity_t), (BYTE *)cmd, aBuf);

    *aLen = 4 + sizeof(caStaSetSecurity_t);

    return ret;
}

int xcCmdProcStaSetPSK(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetPSK_t *setencryp = (caStaSetPSK_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetPSK_t defparams = {"", "", "", "", 0, WFA_DISABLED};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setencryp, (void *)&defparams, sizeof(caStaSetPSK_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setencryp->ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setencryp->ssid);
        }
        else if (strcasecmp(str, "passPhrase") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setencryp->passphrase, str, 63);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setencryp->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setencryp->encrptype, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setencryp->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setencryp->pmf = WFA_REQUIRED;
            else
                setencryp->pmf = WFA_DISABLED;
        }
        else if (strcasecmp(str, "micAlg") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "sha-256") == 0)
                setencryp->micAlg = 256;
            else
                setencryp->micAlg = 0; /* Default SHA-1 if micAlg not specified */
        }
        else if (strcasecmp(str, "prefer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncasecmp(str, "1", 1) == 0)
                setencryp->prefer = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_PSK_TLV, sizeof(caStaSetPSK_t), (BYTE *)setencryp, aBuf);

    *aLen = 4 + sizeof(caStaSetPSK_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetEapTLS(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapTLS_t *setsec = (caStaSetEapTLS_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetEapTLS_t defparams = {"", "", "", "", "", ""};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapTLS_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
            setsec->username_flag = 1;
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 8);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str, 8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "trustedRootCA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->trustedRootCA, str);
        }
        else if (strcasecmp(str, "clientCertificate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->clientCertificate, str);
            strcpy(setsec->clientCertificatekey, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else if (strcasecmp(str, "forced_required") == 0)
                setsec->pmf = WFA_F_REQUIRED;
            else if (strcasecmp(str, "forced_disabled") == 0)
                setsec->pmf = WFA_F_DISABLED;
            else
                setsec->pmf = WFA_DISABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_EAPTLS_TLV, sizeof(caStaSetEapTLS_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapTLS_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetEapTTLS(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapTTLS_t *setsec   = (caStaSetEapTTLS_t *)(aBuf + sizeof(wfaTLV));
    caStaSetEapTTLS_t defparams = {"", "", "", "", "", "", "", ""};
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapTTLS_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->passwd, str);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 7);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str, 8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "trustedRootCA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->trustedRootCA, str);
        }
        else if (strcasecmp(str, "clientCertificate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->clientCertificate, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else
                setsec->pmf = WFA_DISABLED;
        }
        else if (strcasecmp(str, "prefer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncasecmp(str, "1", 1) == 0)
                setsec->prefer = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_EAPTTLS_TLV, sizeof(caStaSetEapTTLS_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapTTLS_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetEapSIM(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapSIM_t *setsec = (caStaSetEapSIM_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetEapSIM_t defparams = {"", "", "", "", "", "", 0};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapSIM_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->passwd, str);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 7);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str,8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else
                setsec->pmf = WFA_DISABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_EAPSIM_TLV, sizeof(caStaSetEapSIM_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapSIM_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetPEAP(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapPEAP_t *setsec = (caStaSetEapPEAP_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetEapPEAP_t defparams = {"", "", "", "", "", "", "", "", 0};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapPEAP_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->passwd, str);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 7);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str, 8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "innerEAP") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->innerEAP, str);
        }
        else if (strcasecmp(str, "trustedRootCA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->trustedRootCA, str, 31);
        }
        else if (strcasecmp(str, "peapVersion") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            setsec->peapVersion = atoi(str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else
                setsec->pmf = WFA_DISABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_PEAP_TLV, sizeof(caStaSetEapPEAP_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapPEAP_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetIBSS(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetIBSS_t *setibss = (caStaSetIBSS_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    int i                    = 0;
    caStaSetIBSS_t defparams = {"", "", 0, 0, {"", "", "", ""}, 0xFF};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setibss, (void *)&defparams, sizeof(caStaSetIBSS_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setibss->intf);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setibss->ssid);
        }
        else if (strcasecmp(str, "channel") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            setibss->channel = atoi(str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "wep") == 0)
                setibss->encpType = ENCRYPT_WEP;
            else
                setibss->encpType = 0;
        }
        else if (strncasecmp(str, "key1", 4) == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->keys[i++], str, 26);
            setibss->activeKeyIdx = 0;
        }
        else if (strncasecmp(str, "key2", 4) == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->keys[i++], str, 26);
        }
        else if (strncasecmp(str, "key3", 4) == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->keys[i++], str, 26);
        }
        else if (strncasecmp(str, "key4", 4) == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setibss->keys[i++], str, 26);
        }
        else if (strcasecmp(str, "activeKey") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            setibss->activeKeyIdx = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_IBSS_TLV, sizeof(caStaSetIBSS_t), (BYTE *)setibss, aBuf);

    *aLen = 4 + sizeof(caStaSetIBSS_t);

    return WFA_SUCCESS;
}

int xcCmdProcDeviceGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *dutCmd = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    caDevInfo_t *dinfo   = &dutCmd->cmdsu.dev;
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    printf("entering device get info\n");
    memset(aBuf, 0, *aLen);

    dinfo->fw = 0;
    str       = strtok_r(NULL, ",", &pcmdStr);
    if (str != NULL && str[0] != '\0')
    {
        if (strcasecmp(str, "firmware") == 0)
        {
            dinfo->fw = 1;
        }
    }

    wfaEncodeTLV(WFA_DEVICE_GET_INFO_TLV, 0, NULL, aBuf);

    *aLen = 4;

    return WFA_SUCCESS;
}

int xcCmdProcStaGetInfo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *getInfo = (dutCommand_t *)(aBuf + sizeof(wfaTLV));

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "interface") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        strncpy(getInfo->intf, str, 15);
        DPRINT_INFO(WFA_OUT, "interface %s\n", getInfo->intf);
    }

    wfaEncodeTLV(WFA_STA_GET_INFO_TLV, sizeof(dutCommand_t), (BYTE *)getInfo, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaUpload(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *dutCmd = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    caStaUpload_t *tdp   = &dutCmd->cmdsu.upload;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "test") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (strcasecmp(str, "voice") == 0)
        {
            tdp->type = WFA_UPLOAD_VHSO_RPT;
            DPRINT_INFO(WFA_OUT, "testdata voice %i\n", tdp->type);
            str       = strtok_r(NULL, ",", &pcmdStr);
            tdp->next = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_UPLOAD_TLV, sizeof(dutCommand_t), (BYTE *)dutCmd, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaAssociate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaAssociate_t *assoc    = &setassoc->cmdsu.assoc;
    caStaAssociate_t defparams = {"", "", WFA_DISABLED};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(assoc, &defparams, sizeof(caStaAssociate_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setassoc->cmdsu.assoc.ssid);
        }
        else if (strcasecmp(str, "bssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.bssid, str, 17);
            DPRINT_INFO(WFA_OUT, "bssid %s\n", setassoc->cmdsu.assoc.bssid);
        }
        else if (strcasecmp(str, "wps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enabled") == 0)
                setassoc->cmdsu.assoc.wps = WFA_ENABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_ASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaReAssociate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaAssociate_t *assoc    = &setassoc->cmdsu.assoc;
    caStaAssociate_t defparams = {"", "", WFA_DISABLED};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(assoc, &defparams, sizeof(caStaAssociate_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.ssid, str, 64);
            DPRINT_INFO(WFA_OUT, "ssid %s\n", setassoc->cmdsu.assoc.ssid);
        }
        else if (strcasecmp(str, "bssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.assoc.bssid, str, 17);
            DPRINT_INFO(WFA_OUT, "bssid %s\n", setassoc->cmdsu.assoc.bssid);
        }
    }

    wfaEncodeTLV(WFA_STA_REASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcDeviceListIF(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *getdevlist = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "interfaceType") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (strcmp(str, "802.11") == 0)
            getdevlist->cmdsu.iftype = IF_80211;

        DPRINT_INFO(WFA_OUT, "interface type %i\n", getdevlist->cmdsu.iftype);
    }

    wfaEncodeTLV(WFA_DEVICE_LIST_IF_TLV, sizeof(dutCommand_t), (BYTE *)getdevlist, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

#if DEBUG
    for (i = 0; i < len; i++)
        printf("%x ", buf[i]);

    printf("\n");
#endif

    return WFA_SUCCESS;
}

int xcCmdProcStaSetUAPSD(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetUAPSD_t *setuapsd = (caStaSetUAPSD_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    wfaTLV *hdr               = (wfaTLV *)aBuf;
    caStaSetUAPSD_t defparams = {"", "", 0, 0, 0, 0, 0};

    DPRINT_INFO(WFA_OUT, "start xcCmdProcAgentConfig ...\n");
    DPRINT_INFO(WFA_OUT, "params:  %s\n", pcmdStr);
    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setuapsd, (void *)&defparams, sizeof(caStaSetUAPSD_t));
    setuapsd->acBE = 0;
    setuapsd->acBK = 0;
    setuapsd->acVI = 0;
    setuapsd->acVO = 0;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setuapsd->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setuapsd->ssid, str, 64);
        }
        else if (strcasecmp(str, "maxSP") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->maxSPLength = atoi(str);
        }
        else if (strcasecmp(str, "acBE") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acBE = atoi(str);
        }
        else if (strcasecmp(str, "acBK") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acBK = atoi(str);
        }
        else if (strcasecmp(str, "acVI") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acVI = atoi(str);
        }
        else if (strcasecmp(str, "acVO") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->acVO = atoi(str);
        }
        else if (strcasecmp(str, "type") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            setuapsd->type = atoi(str);
        }
        else if (strcasecmp(str, "peer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setuapsd->peer, str, 17);
        }
    }
    hdr->tag = WFA_STA_SET_UAPSD_TLV;
    hdr->len = sizeof(caStaSetUAPSD_t);

    memcpy(aBuf + 4, setuapsd, sizeof(caStaSetUAPSD_t));

    *aLen = 4 + sizeof(caStaSetUAPSD_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaDebugSet(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *debugSet = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "level") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (atoi(str) == WFA_DEBUG_INFO || WFA_DEBUG_WARNING)
            {
                debugSet->cmdsu.dbg.level = atoi(str);
                DPRINT_INFO(WFA_OUT, "dbg level %i\n", debugSet->cmdsu.dbg.level);
            }
            else
                return WFA_FAILURE; /* not support */
        }
        else if (strcasecmp(str, "enable") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("enable %i\n", atoi(str));
            switch (atoi(str)) /* enable */
            {
                case 1:
                    debugSet->cmdsu.dbg.state = 1;
                    printf("enable\n");
                    break;
                case 0:
                    debugSet->cmdsu.dbg.state = 0;
                    printf("disable\n");
                    break;
                default:
                    printf("wrong\n");
                    return WFA_FAILURE; /* command invalid */
            }
        }
    }

    wfaEncodeTLV(WFA_STA_DEBUG_SET_TLV, sizeof(dutCommand_t), (BYTE *)debugSet, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetMode(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetMode_t *setmode = (caStaSetMode_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetMode_t defparams = {"", "", 0, 0, 0, {"", "", "", ""}, 0xFF};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setmode, (void *)&defparams, sizeof(caStaSetMode_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmode->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setmode->ssid, str, 64);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "wep") == 0)
                setmode->encpType = ENCRYPT_WEP;
            else
                setmode->encpType = 0;
        }
        else if (strcasecmp(str, "key1") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[0], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[0]);
            setmode->activeKeyIdx = 0;
        }
        else if (strcasecmp(str, "key2") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[1], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[1]);
        }
        else if (strcasecmp(str, "key3") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[2], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[2]);
        }
        else if (strcasecmp(str, "key4") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy((char *)setmode->keys[3], str, 26);
            DPRINT_INFO(WFA_OUT, "%s\n", setmode->keys[3]);
        }
        else if (strcasecmp(str, "activeKey") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            setmode->activeKeyIdx = atoi(str);
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("\r\n mode is %s\n", str);
            if (strcasecmp(str, "adhoc") == 0)
                setmode->mode = 1;
            else
                setmode->mode = 0;
        }
        else if (strcasecmp(str, "channel") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            setmode->channel = atoi(str);
        }
        else
        {
            DPRINT_INFO(WFA_WNG, "Incorrect Command, check syntax\n");
            printf("\r\n mode is %s\n", str);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_MODE_TLV, sizeof(caStaSetMode_t), (BYTE *)setmode, aBuf);
    *aLen = 4 + sizeof(caStaSetMode_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetP2pDevAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *getP2pDevAdd = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(getP2pDevAdd->intf, str, WFA_IF_NAME_LEN - 1);
            getP2pDevAdd->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_GET_DEV_ADDRESS_TLV, sizeof(dutCommand_t), (BYTE *)getP2pDevAdd, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetP2p(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetP2p_t *staSetP2p = (caStaSetP2p_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetP2p->intf, str, WFA_IF_NAME_LEN - 1);
            staSetP2p->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "listen_chn") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->listen_chn      = atoi(str);
            staSetP2p->listen_chn_flag = 1;
        }
        else if (strcasecmp(str, "p2p_mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetP2p->p2p_mode, str, 15);
            staSetP2p->p2p_mode_flag = 1;
        }
        else if (strcasecmp(str, "persistent") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->presistent      = atoi(str);
            staSetP2p->presistent_flag = 1;
        }
        else if (strcasecmp(str, "intra_bss") == 0)
        {
            str                       = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->intra_bss      = atoi(str);
            staSetP2p->intra_bss_flag = 1;
        }
        else if (strcasecmp(str, "noa_duration") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->noa_duration      = atoi(str);
            staSetP2p->noa_duration_flag = 1;
        }
        else if (strcasecmp(str, "noa_interval") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->noa_interval      = atoi(str);
            staSetP2p->noa_interval_flag = 1;
        }
        else if (strcasecmp(str, "noa_count") == 0)
        {
            str                       = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->noa_count      = atoi(str);
            staSetP2p->noa_count_flag = 1;
        }
        else if (strcasecmp(str, "concurrency") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->concurrency      = atoi(str);
            staSetP2p->concurrency_flag = 1;
        }
        else if (strcasecmp(str, "p2pinvitation") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->p2p_invitation      = atoi(str);
            staSetP2p->p2p_invitation_flag = 1;
        }
        else if (strcasecmp(str, "bcn_int") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->bcn_int      = atoi(str);
            staSetP2p->bcn_int_flag = 1;
        }
        else if (strcasecmp(str, "ext_listen_time_interval") == 0)
        {
            str                                 = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->ext_listen_time_int      = atoi(str);
            staSetP2p->ext_listen_time_int_flag = 1;
        }
        else if (strcasecmp(str, "ext_listen_time_period") == 0)
        {
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->ext_listen_time_period      = atoi(str);
            staSetP2p->ext_listen_time_period_flag = 1;
        }
        else if (strcasecmp(str, "discoverability") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->discoverability      = atoi(str);
            staSetP2p->discoverability_flag = 1;
        }
        else if (strcasecmp(str, "service_discovery") == 0)
        {
            str                              = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->service_discovery     = atoi(str);
            staSetP2p->service_discovry_flag = 1;
        }
        else if (strcasecmp(str, "crossconnection") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->crossconnection      = atoi(str);
            staSetP2p->crossconnection_flag = 1;
        }
        else if (strcasecmp(str, "p2pmanaged") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->p2pmanaged      = atoi(str);
            staSetP2p->p2pmanaged_flag = 1;
        }
        else if (strcasecmp(str, "go_apsd") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            staSetP2p->go_apsd      = atoi(str);
            staSetP2p->go_apsd_flag = 1;
        }
        else if (strcasecmp(str, "DiscoverType") == 0)
        {
            staSetP2p->discover_type_flag = 1;

            str = strtok_r(NULL, ",", &pcmdStr);
            printf("DiscoverType is %s\n", str);
            if (strcasecmp(str, "WFD") == 0)
                staSetP2p->discoverType = 1;
            else if (strcasecmp(str, "P2P") == 0)
                staSetP2p->discoverType = 2;
            else if (strcasecmp(str, "TDLS") == 0)
                staSetP2p->discoverType = 3;
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SETP2P_TLV, sizeof(caStaSetP2p_t), (BYTE *)staSetP2p, aBuf);

    *aLen = 4 + sizeof(caStaSetP2p_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaP2pConnect(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaP2pConnect_t *staP2pConnect = (caStaP2pConnect_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pConnect->intf, str, WFA_IF_NAME_LEN - 1);
            staP2pConnect->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pConnect->grpid, str, WFA_P2P_GRP_ID_LEN - 1);
            staP2pConnect->grpid[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pConnect->devId, str, WFA_P2P_DEVID_LEN - 1);
            staP2pConnect->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_CONNECT_TLV, sizeof(caStaP2pConnect_t), (BYTE *)staP2pConnect, aBuf);

    *aLen = 4 + sizeof(caStaP2pConnect_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaP2pStartGroupFormation(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaP2pStartGrpForm_t *staP2pStartGrpForm = (caStaP2pStartGrpForm_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pStartGrpForm->intf, str, WFA_IF_NAME_LEN - 1);
            staP2pStartGrpForm->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pStartGrpForm->devId, str, WFA_P2P_DEVID_LEN - 1);
            staP2pStartGrpForm->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "intent_val") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            staP2pStartGrpForm->intent_val = atoi(str);
        }
        else if (strcasecmp(str, "init_go_neg") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            staP2pStartGrpForm->init_go_neg = atoi(str);
        }
        else if (strcasecmp(str, "oper_chn") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            staP2pStartGrpForm->oper_chn      = atoi(str);
            staP2pStartGrpForm->oper_chn_flag = 1;
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pStartGrpForm->ssid, str, WFA_SSID_NAME_LEN - 1);
            staP2pStartGrpForm->ssid[WFA_SSID_NAME_LEN - 1] = '\0';
            staP2pStartGrpForm->ssid_flag                   = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_START_GRP_FORMATION_TLV, sizeof(caStaP2pStartGrpForm_t), (BYTE *)staP2pStartGrpForm, aBuf);

    *aLen = 4 + sizeof(caStaP2pStartGrpForm_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaP2pDissolve(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaP2pDissolve_t *staP2pDissolve = (caStaP2pDissolve_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pDissolve->intf, str, WFA_IF_NAME_LEN - 1);
            staP2pDissolve->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pDissolve->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staP2pDissolve->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_DISSOLVE_TLV, sizeof(dutCommand_t), (BYTE *)staP2pDissolve, aBuf);

    *aLen = 4 + sizeof(caStaP2pDissolve_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSendP2pInvReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSendP2pInvReq_t *staSendP2pInvReq = (caStaSendP2pInvReq_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pInvReq->intf, str, WFA_IF_NAME_LEN - 1);
            staSendP2pInvReq->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pInvReq->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staSendP2pInvReq->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pInvReq->devId, str, WFA_P2P_DEVID_LEN - 1);
            staSendP2pInvReq->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "reinvoke") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            staSendP2pInvReq->reinvoke = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SEND_INV_REQ_TLV, sizeof(caStaSendP2pInvReq_t), (BYTE *)staSendP2pInvReq, aBuf);

    *aLen = 4 + sizeof(caStaSendP2pInvReq_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaAcceptP2pInvReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaAcceptP2pInvReq_t *staAccceptP2pInvReq = (caStaAcceptP2pInvReq_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staAccceptP2pInvReq->intf, str, WFA_IF_NAME_LEN - 1);
            staAccceptP2pInvReq->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staAccceptP2pInvReq->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staAccceptP2pInvReq->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staAccceptP2pInvReq->devId, str, WFA_P2P_DEVID_LEN - 1);
            staAccceptP2pInvReq->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "reinvoke") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            staAccceptP2pInvReq->reinvoke = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_ACCEPT_INV_REQ_TLV, sizeof(caStaAcceptP2pInvReq_t), (BYTE *)staAccceptP2pInvReq, aBuf);

    *aLen = 4 + sizeof(caStaAcceptP2pInvReq_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSendP2pProvDisReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSendP2pProvDisReq_t *staSendP2pProvDisReq = (caStaSendP2pProvDisReq_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pProvDisReq->intf, str, WFA_IF_NAME_LEN - 1);
            staSendP2pProvDisReq->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "configmethod") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pProvDisReq->confMethod, str, 15);
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pProvDisReq->devId, str, WFA_P2P_DEVID_LEN - 1);
            staSendP2pProvDisReq->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SEND_PROV_DIS_REQ_TLV, sizeof(caStaSendP2pProvDisReq_t), (BYTE *)staSendP2pProvDisReq,
                 aBuf);

    *aLen = 4 + sizeof(caStaSendP2pProvDisReq_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetWpsPbc(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetWpsPbc_t *staSetWpsPbc = (caStaSetWpsPbc_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetWpsPbc->intf, str, WFA_IF_NAME_LEN - 1);
            staSetWpsPbc->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetWpsPbc->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staSetWpsPbc->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
            staSetWpsPbc->grpid_flag                    = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_WPS_SETWPS_PBC_TLV, sizeof(caStaSetWpsPbc_t), (BYTE *)staSetWpsPbc, aBuf);

    *aLen = 4 + sizeof(caStaSetWpsPbc_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaWpsReadPin(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaWpsReadPin_t *staWpsReadPin = (caStaWpsReadPin_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsReadPin->intf, str, WFA_IF_NAME_LEN - 1);
            staWpsReadPin->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsReadPin->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staWpsReadPin->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
            staWpsReadPin->grpid_flag                    = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_WPS_READ_PIN_TLV, sizeof(caStaWpsReadPin_t), (BYTE *)staWpsReadPin, aBuf);

    *aLen = 4 + sizeof(caStaWpsReadPin_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaWpsReadLabel(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaWpsReadLabel_t *staWpsReadLabel = (caStaWpsReadLabel_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsReadLabel->intf, str, WFA_IF_NAME_LEN - 1);
            staWpsReadLabel->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsReadLabel->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staWpsReadLabel->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
            staWpsReadLabel->grpid_flag                    = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_WPS_READ_LABEL_TLV, sizeof(caStaWpsReadLabel_t), (BYTE *)staWpsReadLabel, aBuf);

    *aLen = 4 + sizeof(caStaWpsReadLabel_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaWpsEnterPin(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaWpsEnterPin_t *staWpsEnterPin = (caStaWpsEnterPin_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsEnterPin->intf, str, WFA_IF_NAME_LEN - 1);
            staWpsEnterPin->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "pin") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsEnterPin->wpsPin, str, WFA_WPS_PIN_LEN - 1);
            staWpsEnterPin->wpsPin[WFA_WPS_PIN_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWpsEnterPin->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staWpsEnterPin->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
            staWpsEnterPin->grpid_flag                    = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_WPS_ENTER_PIN_TLV, sizeof(caStaWpsEnterPin_t), (BYTE *)staWpsEnterPin, aBuf);

    *aLen = 4 + sizeof(caStaWpsEnterPin_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetPsk(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaGetPsk_t *staGetPsk = (caStaGetPsk_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGetPsk->intf, str, WFA_IF_NAME_LEN - 1);
            staGetPsk->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGetPsk->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staGetPsk->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_GET_PSK_TLV, sizeof(caStaGetPsk_t), (BYTE *)staGetPsk, aBuf);

    *aLen = 4 + sizeof(caStaGetPsk_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaP2pStartAutoGo(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaStartAutoGo_t *staP2pStartAutoGo = (caStaStartAutoGo_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pStartAutoGo->intf, str, WFA_IF_NAME_LEN - 1);
            staP2pStartAutoGo->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "oper_chn") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            staP2pStartAutoGo->oper_chn = atoi(str);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pStartAutoGo->ssid, str, WFA_SSID_NAME_LEN - 1);
            staP2pStartAutoGo->ssid[WFA_SSID_NAME_LEN - 1] = '\0';
            staP2pStartAutoGo->ssid_flag                   = 1;
        }
        else if (strcasecmp(str, "RTSP") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            staP2pStartAutoGo->rtsp_flag = 1;
            staP2pStartAutoGo->rtsp      = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_START_AUTO_GO_TLV, sizeof(caStaStartAutoGo_t), (BYTE *)staP2pStartAutoGo, aBuf);

    *aLen = 4 + sizeof(caStaStartAutoGo_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaP2pReset(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *staP2pReset = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staP2pReset->intf, str, WFA_IF_NAME_LEN - 1);
            staP2pReset->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_RESET_TLV, sizeof(dutCommand_t), (BYTE *)staP2pReset, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetP2pIpConfig(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaGetP2pIpConfig_t *staGetP2pIpConfig = (caStaGetP2pIpConfig_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGetP2pIpConfig->intf, str, WFA_IF_NAME_LEN - 1);
            staGetP2pIpConfig->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGetP2pIpConfig->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staGetP2pIpConfig->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_GET_IP_CONFIG_TLV, sizeof(caStaGetP2pIpConfig_t), (BYTE *)staGetP2pIpConfig, aBuf);

    *aLen = 4 + sizeof(caStaGetP2pIpConfig_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSendServiceDiscoveryReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSendServiceDiscoveryReq_t *staSendServiceDiscoveryReq =
        (caStaSendServiceDiscoveryReq_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendServiceDiscoveryReq->intf, str, WFA_IF_NAME_LEN - 1);
            staSendServiceDiscoveryReq->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendServiceDiscoveryReq->devId, str, WFA_P2P_DEVID_LEN - 1);
            staSendServiceDiscoveryReq->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SEND_SERVICE_DISCOVERY_REQ_TLV, sizeof(caStaSendServiceDiscoveryReq_t),
                 (BYTE *)staSendServiceDiscoveryReq, aBuf);

    *aLen = 4 + sizeof(caStaSendServiceDiscoveryReq_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSendP2pPresenceReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSendP2pPresenceReq_t *staSendP2pPresenceReq = (caStaSendP2pPresenceReq_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendP2pPresenceReq->intf, str, WFA_IF_NAME_LEN - 1);
            staSendP2pPresenceReq->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "interval") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            staSendP2pPresenceReq->interval = atoll(str);
        }
        else if (strcasecmp(str, "duration") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            staSendP2pPresenceReq->duration = atoll(str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SEND_PRESENCE_REQ_TLV, sizeof(caStaSendP2pPresenceReq_t), (BYTE *)staSendP2pPresenceReq,
                 aBuf);

    *aLen = 4 + sizeof(caStaSendP2pPresenceReq_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetSleepReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetSleep_t *staSetSleep = (caStaSetSleep_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetSleep->intf, str, WFA_IF_NAME_LEN - 1);
            staSetSleep->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetSleep->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staSetSleep->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SET_SLEEP_TLV, sizeof(caStaSetSleep_t), (BYTE *)staSetSleep, aBuf);

    *aLen = 4 + sizeof(caStaSetSleep_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetOpportunistcPsReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetOpprPs_t *staSetOpprPs = (caStaSetOpprPs_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetOpprPs->intf, str, WFA_IF_NAME_LEN - 1);
            staSetOpprPs->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "ctwindow") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            staSetOpprPs->ctwindow = atoi(str);
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetOpprPs->grpId, str, WFA_P2P_GRP_ID_LEN - 1);
            staSetOpprPs->grpId[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_SET_OPPORTUNISTIC_PS_TLV, sizeof(caStaSetOpprPs_t), (BYTE *)staSetOpprPs, aBuf);

    *aLen = 4 + sizeof(caStaSetOpprPs_t);

    return WFA_SUCCESS;
}
int xcCmdProcStaAddARPTableEntry(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaAddARPTableEntry_t *staAddARPTableEntry = (caStaAddARPTableEntry_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staAddARPTableEntry->intf, str, WFA_IF_NAME_LEN - 1);
            staAddARPTableEntry->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "macaddress") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(staAddARPTableEntry->macaddress, str);
        }
        else if (strcasecmp(str, "ipaddress") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(staAddARPTableEntry->ipaddress, str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_ADD_ARP_TABLE_ENTRY_TLV, sizeof(caStaAddARPTableEntry_t), (BYTE *)staAddARPTableEntry,
                 aBuf);

    *aLen = 4 + sizeof(caStaAddARPTableEntry_t);

    return WFA_SUCCESS;
}
int xcCmdProcStaBlockICMPResponse(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaBlockICMPResponse_t *staBlockICMPResponse = (caStaBlockICMPResponse_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staBlockICMPResponse->intf, str, WFA_IF_NAME_LEN - 1);
            staBlockICMPResponse->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(staBlockICMPResponse->grpId, str);
        }
        else if (strcasecmp(str, "ipaddress") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(staBlockICMPResponse->ipaddress, str);
        }
    }

    wfaEncodeTLV(WFA_STA_P2P_ADD_ARP_TABLE_ENTRY_TLV, sizeof(caStaBlockICMPResponse_t), (BYTE *)staBlockICMPResponse,
                 aBuf);

    *aLen = 4 + sizeof(caStaBlockICMPResponse_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetPwrSave(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetPwrSave_t *setps = (caStaSetPwrSave_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setps->intf, str, 15);
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setps->mode, str, 64);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_PWRSAVE_TLV, sizeof(caStaSetPwrSave_t), (BYTE *)setps, aBuf);
    *aLen = 4 + sizeof(caStaSetPwrSave_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetPowerSave(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetPowerSave_t *setps = (caStaSetPowerSave_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setps->intf, str, 15);
        }
        if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
        }
        if (strcasecmp(str, "HE") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            DPRINT_INFO(WFA_OUT, "Divesh:Entering STA SET POWER SAVE FOR HE");
        }
        if (strcasecmp(str, "powersave") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setps->mode, str);
            printf("\n The PowerSave Mode requested is ----%s-----\n", str);
            {
                if (!(strcmp(setps->mode, "on")))
                    setps->ps_flag = 1;
                else
                    setps->ps_flag = 0;
            }
            DPRINT_INFO(WFA_OUT,
                        "\nSETPS_FLAG is set to 1 for PS-ON and 0 for PS-OFF\n---The current value is \"%d\"\n",
                        setps->ps_flag);
        }
    }
    wfaEncodeTLV(WFA_STA_SET_POWER_SAVE_TLV, sizeof(caStaSetPowerSave_t), (BYTE *)setps, aBuf);
    *aLen = 4 + sizeof(caStaSetPowerSave_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetWMM(char *pcmdStr, BYTE *aBuf, int *aLen)
{
#ifdef WFA_WMM_AC
    caStaSetWMM_t *setwmm = (caStaSetWMM_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    wfaTLV *hdr = (wfaTLV *)aBuf;

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaSetWMM ...\n");
    DPRINT_INFO(WFA_OUT, "params:  %s\n", pcmdStr);
    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    /* Some default values, in case they are not specified*/
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setwmm->intf, str, 15);
        }
        else if (strcasecmp(str, "GROUP") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "WMMAC") == 0)
                setwmm->group = GROUP_WMMAC;
            else if (strcasecmp(str, "WMM-CONFIG") == 0)
            {
                setwmm->group                   = GROUP_WMMCONF;
                setwmm->actions.config.frag_thr = 2346;
                setwmm->actions.config.rts_thr  = 2346;
                setwmm->actions.config.wmm      = 1;
            }
        }
        else if (strcasecmp(str, "ACTION") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "addts") == 0)
            {
                // Put default values for the tspec element
                setwmm->action                            = WMMAC_ADDTS;
                setwmm->actions.addts.accesscat           = WMMAC_AC_BE;
                setwmm->actions.addts.tspec.tsinfo.dummy1 = 1;
                setwmm->actions.addts.tspec.tsinfo.dummy2 = 0;
            }
            else if (strcasecmp(str, "delts") == 0)
                setwmm->action = WMMAC_DELTS;
            DPRINT_INFO(WFA_OUT, "action is %d\n", setwmm->action);
        }
        else if (strcasecmp(str, "RTS_thr") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.config.rts_thr = atoi(str);
        }
        else if (strcasecmp(str, "wmm") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (atoi(str) != 0)
                setwmm->actions.config.wmm = 1;
            else
                setwmm->actions.config.wmm = 0;
        }
        else if (strcasecmp(str, "Frag_thr") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.config.frag_thr = atoi(str);
        }
        else if (strcasecmp(str, "DIALOG_TOKEN") == 0)
        {
            str                                = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.dialog_token = atoi(str);
        }
        else if (strcasecmp(str, "TID") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (setwmm->action == WMMAC_ADDTS)
                setwmm->actions.addts.tspec.tsinfo.TID = atoi(str);
            else
                setwmm->actions.delts = atoi(str);
        }
        else if (strcasecmp(str, "SENDTRIG") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "true") == 0)
                setwmm->send_trig = 1;
            else
                setwmm->send_trig = 0;
        }
        else if (strcasecmp(str, "DEST") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setwmm->dipaddr, str, 15);
        }
        else if (strcasecmp(str, "trigac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "VO") == 0)
                setwmm->trig_ac = WMMAC_AC_VO;
            else if (strcasecmp(str, "VI") == 0)
                setwmm->trig_ac = WMMAC_AC_VI;
            else if (strcasecmp(str, "BE") == 0)
                setwmm->trig_ac = WMMAC_AC_BE;
            else if (strcasecmp(str, "BK") == 0)
                setwmm->trig_ac = WMMAC_AC_BK;
        }
        else if (strcasecmp(str, "DIRECTION") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "UP") == 0)
                setwmm->actions.addts.tspec.tsinfo.direction = WMMAC_UPLINK;
            else if (strcasecmp(str, "DOWN") == 0)
                setwmm->actions.addts.tspec.tsinfo.direction = WMMAC_DOWNLINK;
            else if (strcasecmp(str, "BIDI") == 0)
                setwmm->actions.addts.tspec.tsinfo.direction = WMMAC_BIDIR;
        }
        else if (strcasecmp(str, "PSB") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "UAPSD") == 0)
                setwmm->actions.addts.tspec.tsinfo.PSB = 1;
            else
                setwmm->actions.addts.tspec.tsinfo.PSB = 0;
        }
        else if (strcasecmp(str, "UP") == 0)
        {
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.tsinfo.UP = atoi(str);
        }
        else if (strcasecmp(str, "Fixed") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "true") == 0)
                setwmm->actions.addts.tspec.Fixed = 1;
            else
                setwmm->actions.addts.tspec.Fixed = 0;
        }
        // else if(strcasecmp(str, "MSDU") == 0)
        else if (strcasecmp(str, "SIZE") == 0)
        {
            str                              = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.size = atoi(str);
        }
        else if (strcasecmp(str, "MAXSIZE") == 0)
        {
            str                                 = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.maxsize = atoi(str);
        }
        else if (strcasecmp(str, "MIN_SRVC_INTRVL") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.min_srvc = atoi(str);
        }
        else if (strcasecmp(str, "MAX_SRVC_INTRVL") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.max_srvc = atoi(str);
        }
        else if (strcasecmp(str, "INACTIVITY") == 0)
        {
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.inactivity = atoi(str);
        }
        else if (strcasecmp(str, "SUSPENSION") == 0)
        {
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.suspension = atoi(str);
        }
        else if (strcasecmp(str, "SRVCSTARTTIME") == 0)
        {
            str                                       = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.srvc_strt_tim = atoi(str);
        }
        else if (strcasecmp(str, "MINDATARATE") == 0)
        {
            str                                     = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.mindatarate = atoi(str);
        }
        else if (strcasecmp(str, "MEANDATARATE") == 0)
        {
            str                                      = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.meandatarate = atoi(str);
        }
        else if (strcasecmp(str, "PEAKDATARATE") == 0)
        {
            str                                      = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.peakdatarate = atoi(str);
        }
        else if (strcasecmp(str, "BURSTSIZE") == 0 || strcasecmp(str, "MSDUAGGR") == 0)
        {
            // which is used is depending on BurstSizeDef
            // additional checking will be needed.
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.burstsize = atoi(str);
        }
        else if (strcasecmp(str, "DELAYBOUND") == 0)
        {
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.delaybound = atoi(str);
        }
        else if (strcasecmp(str, "PHYRATE") == 0)
        {
            str                                 = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.PHYrate = atoi(str);
        }
        else if (strcasecmp(str, "SBA") == 0)
        {
            str                             = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.sba = atof(str);
        }
        else if (strcasecmp(str, "MEDIUM_TIME") == 0)
        {
            str                                     = strtok_r(NULL, ",", &pcmdStr);
            setwmm->actions.addts.tspec.medium_time = atoi(str);
        }
        else if (strcasecmp(str, "ACCESSCAT") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "VO") == 0)
                setwmm->actions.addts.accesscat = WMMAC_AC_VO;
            else if (strcasecmp(str, "VI") == 0)
                setwmm->actions.addts.accesscat = WMMAC_AC_VI;
            else if (strcasecmp(str, "BE") == 0)
                setwmm->actions.addts.accesscat = WMMAC_AC_BE;
            else if (strcasecmp(str, "BK") == 0)
                setwmm->actions.addts.accesscat = WMMAC_AC_BK;
        }
        else if (strcasecmp(str, "infoAck") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "HT") == 0)
            {
                setwmm->actions.addts.tspec.tsinfo.infoAck = 1;
            }
            else // normal
            {
                setwmm->actions.addts.tspec.tsinfo.infoAck = 0;
            }
        }
        else if (strcasecmp(str, "BurstSizeDef") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "SET") == 0)
            {
                setwmm->actions.addts.tspec.tsinfo.bstSzDef = 1;
            }
            else // CLEAR
            {
                setwmm->actions.addts.tspec.tsinfo.bstSzDef = 0;
            }
        }
    }
    if (setwmm->action == WMMAC_ADDTS)
        printf(
            "ADDTS AC PARAMS: dialog id: %d, TID: %d, DIRECTION: %d, PSB: %d, UP: %d, INFOACK: %d BURST SIZE DEFN: %d\
	 Fixed %d, MSDU Size: %d, Max MSDU Size %d, MIN SERVICE INTERVAL: %d, MAX SERVICE INTERVAL: %d\
        ,INACTIVITY: %d,SUSPENSION %d,SERVICE START TIME: %d,MIN DATARATE: %d,MEAN DATA RATE: %d\
        , PEAK DATA RATE: %d,BURSTSIZE or MSDU Aggreg: %d,DELAY BOUND: %d,PHYRATE: %d, SPLUSBW: %f,MEDIUM TIME: %d, ACCESSCAT: %d\n",
            setwmm->actions.addts.dialog_token, setwmm->actions.addts.tspec.tsinfo.TID,
            setwmm->actions.addts.tspec.tsinfo.direction, setwmm->actions.addts.tspec.tsinfo.PSB,
            setwmm->actions.addts.tspec.tsinfo.UP, setwmm->actions.addts.tspec.tsinfo.infoAck,
            setwmm->actions.addts.tspec.tsinfo.bstSzDef, setwmm->actions.addts.tspec.Fixed,
            setwmm->actions.addts.tspec.size, setwmm->actions.addts.tspec.maxsize, setwmm->actions.addts.tspec.min_srvc,
            setwmm->actions.addts.tspec.max_srvc, setwmm->actions.addts.tspec.inactivity,
            setwmm->actions.addts.tspec.suspension, setwmm->actions.addts.tspec.srvc_strt_tim,
            setwmm->actions.addts.tspec.mindatarate, setwmm->actions.addts.tspec.meandatarate,
            setwmm->actions.addts.tspec.peakdatarate, setwmm->actions.addts.tspec.burstsize,
            setwmm->actions.addts.tspec.delaybound, setwmm->actions.addts.tspec.PHYrate,
            setwmm->actions.addts.tspec.sba, setwmm->actions.addts.tspec.medium_time, setwmm->actions.addts.accesscat);
    else
        printf("DELTS AC PARAMS: TID:  %d\n", setwmm->actions.delts);

    hdr->tag = WFA_STA_SET_WMM_TLV;
    hdr->len = sizeof(caStaSetWMM_t);

    memcpy(aBuf + 4, setwmm, sizeof(caStaSetWMM_t));

    *aLen = 4 + sizeof(caStaSetWMM_t);
#endif
    return WFA_SUCCESS;
}

int xcCmdProcStaSetEapFAST(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapFAST_t *setsec   = (caStaSetEapFAST_t *)(aBuf + sizeof(wfaTLV));
    caStaSetEapFAST_t defparams = {"", "", "", "", "", "", "", "", 0, ""};
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapFAST_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->passwd, str);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 7);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str, 8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "trustedRootCA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->trustedRootCA, str, 31);
        }
        else if (strcasecmp(str, "innerEAP") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->innerEAP, str);
        }
        else if (strcasecmp(str, "validateServer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "yes") == 0)
            {
                setsec->validateServer = 1;
            }
            else if (strcasecmp(str, "no") == 0)
            {
                setsec->validateServer = 0;
            }
        }
        else if (strcasecmp(str, "pacFile") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->pacFileName, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else
                setsec->pmf = WFA_DISABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_EAPFAST_TLV, sizeof(caStaSetEapFAST_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapFAST_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetEapAKA(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetEapAKA_t *setsec = (caStaSetEapAKA_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caStaSetEapAKA_t defparams = {"", "", "", "", "", "", 0};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy((void *)setsec, (void *)&defparams, sizeof(caStaSetEapAKA_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->intf, str, 15);
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setsec->ssid, str, 64);
        }
        else if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->username, str);
        }
        else if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(setsec->passwd, str);
        }
        else if (strcasecmp(str, "keyMgmtType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->keyMgmtType, str, 7);
            strcpy(setsec->keyMgmtType, str);
        }
        else if (strcasecmp(str, "encpType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            // strncpy(setsec->encrptype, str, 8);
            strcpy(setsec->encrptype, str);
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "optional") == 0)
                setsec->pmf = WFA_ENABLED;
            else if (strcasecmp(str, "required") == 0)
                setsec->pmf = WFA_REQUIRED;
            else
                setsec->pmf = WFA_DISABLED;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_EAPAKA_TLV, sizeof(caStaSetEapAKA_t), (BYTE *)setsec, aBuf);

    *aLen = 4 + sizeof(caStaSetEapAKA_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetSystime(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetSystime_t *systime = (caStaSetSystime_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "month") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            systime->month = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n month %i \n", systime->month);
        }
        else if (strcasecmp(str, "date") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            systime->date = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n date %i \n", systime->date);
        }
        else if (strcasecmp(str, "year") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            systime->year = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n year %i \n", systime->year);
        }
        else if (strcasecmp(str, "hours") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            systime->hours = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n hours %i \n", systime->hours);
        }
        else if (strcasecmp(str, "minutes") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            systime->minutes = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n minutes %i \n", systime->minutes);
        }

        else if (strcasecmp(str, "seconds") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            systime->seconds = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n seconds %i \n", systime->seconds);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_SYSTIME_TLV, sizeof(caStaSetSystime_t), (BYTE *)systime, aBuf);

    *aLen = 4 + sizeof(caStaSetSystime_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaDisconnect(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *disc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(disc->intf, str, WFA_IF_NAME_LEN - 1);
            disc->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_DISCONNECT_TLV, sizeof(dutCommand_t), (BYTE *)disc, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);
    return WFA_SUCCESS;
}

#ifdef WFA_STA_TB
/* Check for enable/disable and return WFA_ENABLE/WFA_DISABLE. WFA_INVALID_BOOL if invalid */
int wfaStandardBoolParsing(char *str)
{
    int rc;

    if (strcasecmp(str, "enable") == 0)
        rc = WFA_ENABLED;
    else if (strcasecmp(str, "disable") == 0)
        rc = WFA_DISABLED;
    else
        rc = WFA_INVALID_BOOL;

    return rc;
}

#endif
int xcCmdProcStaSendNeigReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *getInfo = (dutCommand_t *)(aBuf + sizeof(wfaTLV));

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    str = strtok_r(NULL, ",", &pcmdStr);
    if (str == NULL || str[0] == '\0')
        return WFA_FAILURE;

    if (strcasecmp(str, "interface") == 0)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        strncpy(getInfo->intf, str, 15);
        DPRINT_INFO(WFA_OUT, "interface %s\n", getInfo->intf);
    }

    wfaEncodeTLV(WFA_STA_SEND_NEIGREQ_TLV, sizeof(dutCommand_t), (BYTE *)getInfo, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}
int xcCmdProcStaDevSendFrame(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *cmd       = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    caStaDevSendFrame_t *sf = &cmd->cmdsu.sf;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(cmd->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "PMF") == 0)
            {
                pmfFrame_t *pmf = &sf->frameType.pmf;

                sf->program = PROG_TYPE_PMF;

                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "framename") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "disassoc") == 0)
                        {
                            pmf->eFrameName = PMF_TYPE_DISASSOC;
                        }
                        else if (strcasecmp(str, "saquery") == 0)
                        {
                            pmf->eFrameName = PMF_TYPE_SAQUERY;
                        }
                        else if (strcasecmp(str, "assocreq") == 0)
                        {
                            pmf->eFrameName = PMF_TYPE_ASSOCREQ;
                        }
                        else if (strcasecmp(str, "reassocreq") == 0)
                        {
                            pmf->eFrameName = PMF_TYPE_REASSOCREQ;
                        }
                        else if (strcasecmp(str, "deauth") == 0)
                        {
                            pmf->eFrameName = PMF_TYPE_DEAUTH;
                        }
                    }
                    else if (strcasecmp(str, "protected") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "correctKey") == 0)
                        {
                            pmf->eProtected = PMF_PROT_CORRECTKEY;
                        }
                        else if (strcasecmp(str, "incorrectKey") == 0)
                        {
                            pmf->eProtected = PMF_PROT_INCORRECTKEY;
                        }
                        else if (strcasecmp(str, "unprotected") == 0)
                        {
                            pmf->eProtected = PMF_PROT_UNPROTECTED;
                        }
                    }
                    else if (strcasecmp(str, "stationid") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pmf->staid, str, WFA_MAC_ADDR_STR_LEN - 1);
                        pmf->staid[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                    }
                    else if (strcasecmp(str, "sender") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pmf->sender, str, 7);
                        pmf->sender[7]   = '\0';
                        pmf->sender_flag = 1;
                    }
                    else if (strcasecmp(str, "bssid") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pmf->bssid, str, WFA_MAC_ADDR_STR_LEN - 1);
                        pmf->bssid[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                        pmf->bssid_flag                      = 1;
                    }
                } /* for */
            }     /* if PMF */
            else if (strcasecmp(str, "TDLS") == 0)
            {
                tdlsFrame_t *tdls = &sf->frameType.tdls;

                sf->program = PROG_TYPE_TDLS;
                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "Type") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "discovery") == 0)
                        {
                            tdls->eFrameName = TDLS_TYPE_DISCOVERY;
                        }
                        else if (strcasecmp(str, "setup") == 0)
                        {
                            tdls->eFrameName = TDLS_TYPE_SETUP;
                        }
                        else if (strcasecmp(str, "teardown") == 0)
                        {
                            tdls->eFrameName = TDLS_TYPE_TEARDOWN;
                        }
                        else if (strcasecmp(str, "channelswitch") == 0)
                        {
                            tdls->eFrameName = TDLS_TYPE_CHANNELSWITCH;
                        }
                        else if (strcasecmp(str, "psnull") == 0)
                        {
                            tdls->eFrameName = TDLS_TYPE_NULLFRAME;
                        }
                    }
                    else if (strcasecmp(str, "peer") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(tdls->peer, str, WFA_MAC_ADDR_STR_LEN - 1);
                        tdls->peer[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                    }
                    else if (strcasecmp(str, "timeout") == 0)
                    {
                        str           = strtok_r(NULL, ",", &pcmdStr);
                        tdls->timeout = atoi(str);
                        if (tdls->timeout < 301)
                            return WFA_FAILURE;

                        tdls->timeout_flag = 1;
                    }
                    else if (strcasecmp(str, "bssid") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(tdls->bssid, str, WFA_MAC_ADDR_STR_LEN - 1);
                        tdls->bssid[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                        tdls->bssid_flag                      = 1;
                    }
                    else if (strcasecmp(str, "switchtime") == 0)
                    {
                        str                   = strtok_r(NULL, ",", &pcmdStr);
                        tdls->switchtime      = atoi(str);
                        tdls->switchtime_flag = 1;
                    }
                    else if (strcasecmp(str, "channel") == 0)
                    {
                        str                = strtok_r(NULL, ",", &pcmdStr);
                        tdls->channel      = atoi(str);
                        tdls->channel_flag = 1;
                    }
                    else if (strcasecmp(str, "channelOffset") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(tdls->offset, str, 4);
                        tdls->offset[3]   = 1;
                        tdls->offset_flag = 1;
                    }
                    else if (strcasecmp(str, "status") == 0)
                    {
                        str          = strtok_r(NULL, ",", &pcmdStr);
                        tdls->status = atoi(str);
                        if (tdls->status != 0 && tdls->status != 37)
                            return WFA_FAILURE;
                        tdls->status_flag = 1;
                    }
                    else if (strcasecmp(str, "reason") == 0)
                    {
                        str               = strtok_r(NULL, ",", &pcmdStr);
                        tdls->reason      = atoi(str);
                        tdls->reason_flag = 1;
                    }
                } /* for */
            }     /* TDLS */
            else if (strcasecmp(str, "VENT") == 0)
            {
                ventFrame_t *vent = &sf->frameType.vent;

                sf->program = PROG_TYPE_VENT;
                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "framename") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "neigreq") == 0)
                        {
                            vent->type = VENT_TYPE_NEIGREQ;
                        }
                        if (strcasecmp(str, "transmgmt") == 0)
                        {
                            vent->type = VENT_TYPE_TRANSMGMT;
                            str        = strtok_r(NULL, ",", &pcmdStr);
                            strncpy(vent->ssid, str, WFA_SSID_NAME_LEN);
                        }
                    }
                }
            }
            else if (strcasecmp(str, "WFD") == 0)
            {
                wfdFrame_t *wfd = &sf->frameType.wfd;

                sf->program = PROG_TYPE_WFD;
                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;
                    if (strcasecmp(str, "framename") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "wfd_probereq") == 0)
                        {
                            wfd->eframe = WFD_FRAME_PRBREQ;
                        }
                        if (strcasecmp(str, "rtsp") == 0)
                        {
                            wfd->eframe = WFD_FRAME_RTSP;
                        }
                        if (strcasecmp(str, "WFD_ServDiscReq") == 0)
                        {
                            wfd->eframe = WFD_FRAME_SERVDISC_REQ;
                        }
                        if (strcasecmp(str, "WFD_ProbeReqTdls") == 0)
                        {
                            wfd->eframe = WFD_FRAME_PRBREQ_TDLS_REQ;
                        }
                        if (strcasecmp(str, "11v_TimingMsrReq") == 0)
                        {
                            wfd->eframe = WFD_FRAME_11V_TIMING_MSR_REQ;
                        }
                    }
                    else if (strcasecmp(str, "source") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(wfd->sa, str, WFA_MAC_ADDR_STR_LEN - 1);
                        wfd->sa[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                    }
                    else if (strcasecmp(str, "destination") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(wfd->da, str, WFA_MAC_ADDR_STR_LEN - 1);
                        wfd->da[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                    }
                    else if (strcasecmp(str, "devtype") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "source") == 0)
                        {
                            wfd->eDevType = WFD_DEV_TYPE_SOURCE;
                        }
                        if (strcasecmp(str, "p-sink") == 0)
                        {
                            wfd->eDevType = WFD_DEV_TYPE_PSINK;
                        }
                        if (strcasecmp(str, "s-sink") == 0)
                        {
                            wfd->eDevType = WFD_DEV_TYPE_SSINK;
                        }

                        wfd->devtype_flag = 1;
                    }
                    else if (strcasecmp(str, "rtspmsgtype") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "pause") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_PAUSE;
                        }
                        if (strcasecmp(str, "play") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_PLAY;
                        }
                        if (strcasecmp(str, "teardown") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_TEARDOWN;
                        }
                        if (strcasecmp(str, "trigger-pause") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_TRIG_PAUSE;
                        }
                        if (strcasecmp(str, "trigger-play") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_TRIG_PLAY;
                        }
                        if (strcasecmp(str, "trigger-teardown") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_TRIG_TEARDOWN;
                        }
                        if (strcasecmp(str, "set_parameter") == 0)
                        {
                            wfd->eRtspMsgType = WFD_RTSP_SET_PARAMETER;
                        }
                        wfd->rtspmsg_flag = 1;
                    }
                    else if (strcasecmp(str, "wfdsession") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(wfd->wfdSessionID, str, WFA_WFD_SESSION_ID_LEN - 1);
                        wfd->wfdSessionID[WFA_WFD_SESSION_ID_LEN - 1] = '\0';
                        wfd->wfdsessionid_flag                        = 1;
                    }
                    else if (strcasecmp(str, "setparameter") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "capUibcKeyBoard") == 0)
                        {
                            wfd->eSetParams = WFD_CAP_UIBC_KEYBOARD;
                        }
                        if (strcasecmp(str, "CapUibcMouse") == 0)
                        {
                            wfd->eSetParams = WFD_CAP_UIBC_MOUSE;
                        }
                        if (strcasecmp(str, "capReNego") == 0)
                        {
                            wfd->eSetParams = WFD_CAP_RE_NEGO;
                        }
                        if (strcasecmp(str, "standBy") == 0)
                        {
                            wfd->eSetParams = WFD_STANDBY;
                        }
                        if (strcasecmp(str, "UibcSettingEnable") == 0)
                        {
                            wfd->eSetParams = WFD_UIBC_SETTINGS_ENABLE;
                        }
                        if (strcasecmp(str, "UibcSettingDisable") == 0)
                        {
                            wfd->eSetParams = WFD_UIBC_SETTINGS_DISABLE;
                        }
                        if (strcasecmp(str, "route_audio") == 0)
                        {
                            wfd->eSetParams = WFD_ROUTE_AUDIO;
                        }
                        if (strcasecmp(str, "3dVideoParam") == 0)
                        {
                            wfd->eSetParams = WFD_3D_VIDEOPARAM;
                        }
                        if (strcasecmp(str, "2dVideoParam") == 0)
                        {
                            wfd->eSetParams = WFD_2D_VIDEOPARAM;
                        }
                        wfd->setparm_flag = 1;
                    }
                    else if (strcasecmp(str, "audioDest") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "p-sink") == 0)
                        {
                            wfd->eAudioDest = WFD_DEV_TYPE_PSINK;
                        }
                        if (strcasecmp(str, "s-sink") == 0)
                        {
                            wfd->eAudioDest = WFD_DEV_TYPE_SSINK;
                        }
                        wfd->audioDest_flag = 1;
                    }
                    else if (strcasecmp(str, "bssid") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(wfd->bssid, str, WFA_MAC_ADDR_STR_LEN - 1);
                        wfd->bssid[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
                        wfd->bssid_flag                      = 1;
                    }
                    else if (strcasecmp(str, "MsrReqAction") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "enable") == 0)
                        {
                            wfd->eMsrAction = eEnable;
                        }
                        else
                        {
                            wfd->eMsrAction = eDisable;
                        }
                        wfd->msrReqAction_flag = 1;
                    }
                    else if (strcasecmp(str, "CapReNegotiateParam") == 0)
                    {
                        int temp1;
                        char *tstr1, *tstr2;
                        wfd->capReNego_flag = 1;
                        str                 = strtok_r(NULL, ",", &pcmdStr);
                        printf("\n The Video format is : %s", str);

                        tstr1 = strtok_r(str, "-", &str);
                        tstr2 = strtok_r(str, "-", &str);

                        temp1 = atoi(tstr2);
                        printf("\n The Video format is : %s****%d*****", tstr1, temp1);

                        if (strcasecmp(tstr1, "cea") == 0)
                        {
                            wfd->ecapReNego = eCEA + 1 + temp1;
                        }
                        else if (strcasecmp(tstr1, "vesa") == 0)
                        {
                            wfd->ecapReNego = eVesa + 1 + temp1;
                        }
                        else
                        {
                            wfd->ecapReNego = eHH + 1 + temp1;
                        }
                    }
                }
            }
            else if (strcasecmp(str, "11n") == 0)
            {
            }
            else if (strcasecmp(str, "VHT") == 0)
            {
                sf->program = PROG_TYPE_VHT5G;
                str         = strtok_r(NULL, ",", &pcmdStr);
                printf("STA opt_md_notif: %s\n", str);
                if (strcasecmp(str, "framename") == 0)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    printf("STA opt_md_notif: %s\n", str);
                    if (strcasecmp(str, "Op_md_notif_frm") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        printf("STA opt_md_notif: %s\n", str);
                        strcpy(sf->frameType.vht5g.frameName, "Op_md_notif_frm");
                        str = strtok_r(NULL, ",", &pcmdStr);
                        str = strtok_r(NULL, ",", &pcmdStr);
                        printf("STA opt_md_notif: %s\n", str);
                        if (strcasecmp(str, "Channel_width") == 0)
                        {
                            str = strtok_r(NULL, ",", &pcmdStr);
                            printf("STA opt_md_notif: %s\n", str);
                            sf->frameType.vht5g.para.opt_md.channel_width = atoi(str);
                            str                                           = strtok_r(NULL, ",", &pcmdStr);
                            if (strcasecmp(str, "NSS") == 0)
                            {
                                str                                 = strtok_r(NULL, ",", &pcmdStr);
                                sf->frameType.vht5g.para.opt_md.nss = atoi(str);
                            }
                        }
                    }
                }
            }
            else if (strcasecmp(str, "MBO") == 0)
            {
                MBO_Frame_t *mbo = &sf->frameType.mbo;
                sf->program      = PROG_TYPE_MBO;

                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "dest") == 0 || strcasecmp(str, "DestMac") == 0)
                    {
                        if (is_valid_runtime_config_param("runtime_config", "dest"))
                        {
                            read_ini_config(SIGMA_USER_CONFIG, "runtime_config", "dest", str);
                        }
                        else
                        {
                            str = strtok_r(NULL, ",", &pcmdStr);
                        }
                        strncpy(mbo->dest, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "dest %s\n", mbo->dest);
                    }

                    if (strcasecmp(str, "FrameName") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "BTMQuery") == 0)
                        {
                            mbo->BTMQuery = 1;
                            DPRINT_INFO(WFA_OUT, "BTM Query is  %d\n", mbo->BTMQuery);
                        }

                        if (strcasecmp(str, "BTMReq") == 0)
                        {
                            mbo->BTMReq = 1;
                            DPRINT_INFO(WFA_OUT, "BTMReq is  %d\n", mbo->BTMReq);
                        }

                        if (strcasecmp(str, "BcnRptReq") == 0)
                        {
                            mbo->BcnRptReq = 1;
                            DPRINT_INFO(WFA_OUT, "BcnRptReq is  %d\n", mbo->BcnRptReq);
                        }

                        if (strcasecmp(str, "WNM_Notify") == 0)
                        {
                            mbo->WNM_Notify = 1;
                            DPRINT_INFO(WFA_OUT, "WNM Notify is  %d\n", mbo->WNM_Notify);
                        }

                        if (strcasecmp(str, "ANQPQuery") == 0)
                        {
                            mbo->ANQPQuery = 1;
                            DPRINT_INFO(WFA_OUT, "ANQPQuery is  %d\n", mbo->ANQPQuery);
                        }
                    }

                    if (strcasecmp(str, "ANQPQuery_ID") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "NeighborReportReq") == 0)
                        {
                            mbo->NeighborReportReq = 1;
                            DPRINT_INFO(WFA_OUT, "NeighborReportReq is  %d\n", mbo->NeighborReportReq);
                        }
                        if (strcasecmp(str, "QueryListWithCellPref") == 0)
                        {
                            mbo->QueryListWithCellPref = 1;
                            DPRINT_INFO(WFA_OUT, "QueryListWithCellPref is  %d\n", mbo->QueryListWithCellPref);
                        }
                    }

                    if (strcasecmp(str, "WNM_Notify_Element") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "CellularCapabilities") == 0)
                        {
                            mbo->CellularCapabilities = 1;
                            DPRINT_INFO(WFA_OUT, "CellularCapabilities is  %d\n", mbo->CellularCapabilities);
                        }

                        if (strcasecmp(str, "NonPrefChanReport") == 0)
                        {
                            mbo->NonPrefChanReport = 1;
                            DPRINT_INFO(WFA_OUT, "NonPrefChanReport is  %d\n", mbo->NonPrefChanReport);
                        }
                    }

                    if (strcasecmp(str, "Cand_List") == 0)
                    {
                        if (is_valid_runtime_config_param("runtime_config", "Cand_List"))
                        {
                            read_ini_config(SIGMA_USER_CONFIG, "runtime_config", "Cand_List", str);
                        }
                        else
                        {
                            str = strtok_r(NULL, ",", &pcmdStr);
                        }
                        if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "1") == 0)
                            mbo->cand_list = 1;
                        else
                            mbo->cand_list = 0;
                        DPRINT_INFO(WFA_OUT, "Cand List %d\n", mbo->cand_list);
                    }
                    if (strcasecmp(str, "Request_Mode") == 0)
                    {
                        if (is_valid_runtime_config_param("runtime_config", "Request_Mode"))
                        {
                            read_ini_config(SIGMA_USER_CONFIG, "runtime_config", "Request_Mode", str);
                        }
                        else
                        {
                            str = strtok_r(NULL, ",", &pcmdStr);
                        }
                        if (strcasecmp(str, "enable") == 0 || strcasecmp(str, "1") == 0)
                            mbo->Request_Mode = 1;
                        else
                            mbo->Request_Mode = 0;
                        DPRINT_INFO(WFA_OUT, "Request Mode %d\n", mbo->Request_Mode);
                    }
                    if (strcasecmp(str, "BTMQuery_Reason_Code") == 0)
                    {
                        if (is_valid_runtime_config_param("runtime_config", "BTMQuery_Reason_Code"))
                        {
                            read_ini_config(SIGMA_USER_CONFIG, "runtime_config", "BTMQuery_Reason_Code", str);
                        }
                        else
                        {
                            str = strtok_r(NULL, ",", &pcmdStr);
                        }
                        mbo->BTMQuery_Reason_Code = atoi(str);
                        DPRINT_INFO(WFA_OUT, "BTMQuery_Reason_Code %d\n", mbo->BTMQuery_Reason_Code);
                    }
                    if (strcasecmp(str, "APChanRpt") == 0)
                    {
                        str                 = strtok_r(NULL, ",", &pcmdStr);
                        mbo->APChanRpt      = atoi(str);
                        mbo->APChanRpt_flag = 1;
                        DPRINT_INFO(WFA_OUT, "APChanRpt_flag %d\n", mbo->APChanRpt_flag);
                    }
                    if (strcasecmp(str, "BTMQuery_Reason_Code") == 0)
                    {
                        str                            = strtok_r(NULL, ",", &pcmdStr);
                        mbo->BTMQuery_Reason_Code      = atoi(str);
                        mbo->BTMQuery_Reason_Code_flag = 1;
                        DPRINT_INFO(WFA_OUT, "BTMQuery_Reason_Code_flag %d\n", mbo->BTMQuery_Reason_Code_flag);
                    }
                    if (strcasecmp(str, "Disassoc_Timer") == 0)
                    {
                        str                      = strtok_r(NULL, ",", &pcmdStr);
                        mbo->Disassoc_Timer      = atoi(str);
                        mbo->Disassoc_Timer_flag = 1;
                        DPRINT_INFO(WFA_OUT, "Disassoc_Timer_flag %d\n", mbo->Disassoc_Timer_flag);
                    }
                    if (strcasecmp(str, "Channel") == 0)
                    {
                        str               = strtok_r(NULL, ",", &pcmdStr);
                        mbo->Channel      = atoi(str);
                        mbo->Channel_flag = 1;
                        DPRINT_INFO(WFA_OUT, "Channel_flag %d\n", mbo->Channel_flag);
                    }
                    if (strcasecmp(str, "MeaDur") == 0)
                    {
                        str              = strtok_r(NULL, ",", &pcmdStr);
                        mbo->MeaDur      = atoi(str);
                        mbo->MeaDur_flag = 1;
                        DPRINT_INFO(WFA_OUT, "MeaDur_flag %d\n", mbo->MeaDur_flag);
                    }
                    if (strcasecmp(str, "MeaDurMand") == 0)
                    {
                        str                  = strtok_r(NULL, ",", &pcmdStr);
                        mbo->MeaDurMand      = atoi(str);
                        mbo->MeaDurMand_flag = 1;
                        DPRINT_INFO(WFA_OUT, "MeaDurMand_flag %d\n", mbo->MeaDurMand_flag);
                    }
                    if (strcasecmp(str, "MeaMode") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->MeaMode, str);
                        mbo->MeaMode_flag = 1;
                        DPRINT_INFO(WFA_OUT, "MeaMode_flag %d\n", mbo->MeaMode_flag);
                    }
                    if (strcasecmp(str, "Name") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->Name, str);
                        mbo->Name_flag = 1;
                        DPRINT_INFO(WFA_OUT, "Name_flag %d\n", mbo->Name_flag);
                    }
                    if (strcasecmp(str, "RandInt") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->RandInt, str);
                        mbo->RandInt_flag = 1;
                        DPRINT_INFO(WFA_OUT, "RandInt_flag %d\n", mbo->RandInt_flag);
                    }
                    if (strcasecmp(str, "RegClass") == 0)
                    {
                        str                = strtok_r(NULL, ",", &pcmdStr);
                        mbo->RegClass      = atoi(str);
                        mbo->RegClass_flag = 1;
                        DPRINT_INFO(WFA_OUT, "RegClass_flag %d\n", mbo->RegClass_flag);
                    }
                    if (strcasecmp(str, "ReqInfo") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->ReqInfo, str);
                        mbo->ReqInfo_flag = 1;
                        DPRINT_INFO(WFA_OUT, "ReqInfo_flag %d\n", mbo->ReqInfo_flag);
                    }
                    if (strcasecmp(str, "RptCond") == 0)
                    {
                        str               = strtok_r(NULL, ",", &pcmdStr);
                        mbo->RptCond      = atoi(str);
                        mbo->RptCond_flag = 1;
                        DPRINT_INFO(WFA_OUT, "RptCond_flag %d\n", mbo->RptCond_flag);
                    }
                    if (strcasecmp(str, "RptDet") == 0)
                    {
                        str              = strtok_r(NULL, ",", &pcmdStr);
                        mbo->RptDet      = atoi(str);
                        mbo->RptDet_flag = 1;
                        DPRINT_INFO(WFA_OUT, "RptDet_flag %d\n", mbo->RptDet_flag);
                    }
                    if (strcasecmp(str, "SSID") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->SSID, str);
                        mbo->SSID_flag = 1;
                        DPRINT_INFO(WFA_OUT, "SSID_flag %d\n", mbo->SSID_flag);
                    }
                    if (strcasecmp(str, "ANQPQuery_ID") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->ANQPQuery_ID, str);
                        mbo->ANQPQuery_ID_flag = 1;
                        DPRINT_INFO(WFA_OUT, "ANQPQuery_ID_flag %d\n", mbo->ANQPQuery_ID_flag);
                    }
                    if (strcasecmp(str, "WNM_Notify_Element") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strcpy(mbo->WNM_Notify_Element, str);
                        mbo->WNM_Notify_Element_flag = 1;
                        DPRINT_INFO(WFA_OUT, "WNM_Notify_Element_flag %d\n", mbo->WNM_Notify_Element_flag);
                    }
                    if (strcasecmp(str, "Request_Mode") == 0)
                    {
                        str                    = strtok_r(NULL, ",", &pcmdStr);
                        mbo->Request_Mode      = atoi(str);
                        mbo->Request_Mode_flag = 1;
                        DPRINT_INFO(WFA_OUT, "Request_Mode_flag %d\n", mbo->Request_Mode_flag);
                    }
                }
            }
            else if (strcasecmp(str, "HS2-R2") == 0 || strcasecmp(str, "HS2") == 0)
            {
                HS2_Frame_t *hs2 = &sf->frameType.hs2;
                sf->program      = PROG_TYPE_HS2;

                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "interface") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(cmd->intf, str, 15);
                        DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
                    }
                    if (strcasecmp(str, "dest") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(hs2->dest, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "dest %s\n", hs2->dest);
                    }
                    if (strcasecmp(str, "srcmac") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(hs2->srcmac, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "srcmac %s\n", hs2->srcmac);
                    }
                    if (strcasecmp(str, "SenderMAC") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(hs2->sendermac, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "sendermac %s\n", hs2->sendermac);
                    }
                    if (strcasecmp(str, "DestIP") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(hs2->destip, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "destip %s\n", hs2->destip);
                    }
                    if (strcasecmp(str, "SenderIP") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(hs2->srcip, str, WFA_MAC_ADDR_STR_LEN - 1);
                        DPRINT_INFO(WFA_OUT, "SenderIP %s\n", hs2->srcip);
                    }
                    if (strcasecmp(str, "FrameName") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "ARPReply") == 0)
                        {
                            hs2->ARPREPLY = 1;
                            DPRINT_INFO(WFA_OUT, "arp reply is  %d\n", hs2->ARPREPLY);
                        }
                        if (strcasecmp(str, "DLSrequest") == 0)
                        {
                            hs2->DLSrequest = 1;
                            DPRINT_INFO(WFA_OUT, "DLSrequest is %d\n", hs2->DLSrequest);
                        }
                        if (strcasecmp(str, "ARPProbe") == 0)
                        {
                            hs2->arpProbe = 1;
                            DPRINT_INFO(WFA_OUT, "ARPProbe is  %d\n", hs2->arpProbe);
                        }
                        if (strcasecmp(str, "ARPAnnounce") == 0)
                        {
                            hs2->arpAnnounce = 1;
                            DPRINT_INFO(WFA_OUT, "ARPAnnounce is  %d\n", hs2->arpAnnounce);
                        }
                        if (strcasecmp(str, "NeighSolicitReq") == 0)
                        {
                            hs2->neighSolicitReq = 1;
                            DPRINT_INFO(WFA_OUT, "NeighSolicitReq is  %d\n", hs2->neighSolicitReq);
                        }
                        if (strcasecmp(str, "anqpquery") == 0)
                        {
                            for (;;)
                            {
                                str = strtok_r(NULL, ",", &pcmdStr);
                                if (str == NULL || str[0] == '\0')
                                    break;
                                if (strcasecmp(str, "Anqp_Cap_List") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->anqpCapList = 1;
                                        DPRINT_INFO(WFA_OUT, "Anqp_Cap_List is %d\n", hs2->anqpCapList);
                                    }
                                }
                                if (strcasecmp(str, "nai_realm_list") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->nairealmlist = 1;
                                        DPRINT_INFO(WFA_OUT, "nai_realm_list is %d\n", hs2->nairealmlist);
                                    }
                                }
                                if (strcasecmp(str, "domain_list") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->domainlist = 1;
                                        DPRINT_INFO(WFA_OUT, "domain_list is %d\n", hs2->domainlist);
                                    }
                                }
                                if (strcasecmp(str, "3gpp_info") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->g3ppinfo = 1;
                                        DPRINT_INFO(WFA_OUT, "3gpp_info is %d\n", hs2->g3ppinfo);
                                    }
                                }
                                if (strcasecmp(str, "hs_cap_list") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->hscaplist = 1;
                                        DPRINT_INFO(WFA_OUT, "hs_cap_list is %d\n", hs2->hscaplist);
                                    }
                                }
                                if (strcasecmp(str, "oper_name") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->opername = 1;
                                        DPRINT_INFO(WFA_OUT, "nai_realm_list is %d\n", hs2->opername);
                                    }
                                }
                                if (strcasecmp(str, "wan_mat") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->wanmat = 1;
                                        DPRINT_INFO(WFA_OUT, "wan_mat is %d\n", hs2->wanmat);
                                    }
                                }
                                if (strcasecmp(str, "venue_name") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->venuename = 1;
                                        DPRINT_INFO(WFA_OUT, "venue_name is %d\n", hs2->venuename);
                                    }
                                }
                                if (strcasecmp(str, "nai_home_realm_list") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->naihomerealmlist = 1;
                                        DPRINT_INFO(WFA_OUT, "nai_home_realm_list is %d\n", hs2->naihomerealmlist);
                                    }
                                }
                                if (strcasecmp(str, "op_class") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->opclass = 1;
                                        DPRINT_INFO(WFA_OUT, "op_class is %d\n", hs2->opclass);
                                    }
                                }
                                if (strcasecmp(str, "NET_AUTH_TYPE") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->netAuthType = 1;
                                        DPRINT_INFO(WFA_OUT, "netAuthType is %d\n", hs2->netAuthType);
                                    }
                                }
                                if (strcasecmp(str, "OSU_PROVIDER_LIST") == 0)
                                {
                                    str = strtok_r(NULL, ",", &pcmdStr);
                                    if (strncasecmp(str, "1", 1) == 0)
                                    {
                                        hs2->osuProviderlist = 1;
                                        DPRINT_INFO(WFA_OUT, "osuProviderlist is %d\n", hs2->osuProviderlist);
                                    }
                                }
                                if (strcasecmp(str, "ICON_REQUEST") == 0)
                                {
                                    str                  = strtok_r(NULL, ",", &pcmdStr);
                                    hs2->iconRequestList = 1;
                                    strncpy(hs2->iconRequest, str, 50);
                                    DPRINT_INFO(WFA_OUT, "iconRequest is %s\n", hs2->iconRequest);
                                }
                            }
                        }
                    }
                }
            }
            /*	else if (strcasecmp(str,"LOC") ==0)
             {

                          WLS_Frame_t *wls = &sf->frameType.wls;
                          sf->program= PROG_TYPE_WLS;

                          for(;;)
                          {
                              str = strtok_r(NULL, ",", &pcmdStr);
                              if(str == NULL || str[0] == '\0')
                                  break;

               if(strcasecmp(str, "interface") == 0)
                     {
                         str = strtok_r(NULL, ",", &pcmdStr);
                         strncpy(wls->intf, str, 15);
                         DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
                     }
               if(strcasecmp(str, "destmac") == 0)
                     {
                         str = strtok_r(NULL, ",", &pcmdStr);
                         strncpy(wls->destmac, str, WFA_MAC_ADDR_STR_LEN-1);
                         DPRINT_INFO(WFA_OUT, "destmac %s\n", wls->destmac);
                     }
               if(strcasecmp(str, "MsntType") == 0)
                     {
                         str = strtok_r(NULL, ",", &pcmdStr);
                wls->MsntType = atoi(str);
                         DPRINT_INFO(WFA_OUT, "MsntType %d\n", wls->MsntType);
                     }
               if(strcasecmp(str, "framename") == 0)
                     {
                         str = strtok_r(NULL, ",", &pcmdStr);
                strcpy(wls->framename, str);
                         DPRINT_INFO(WFA_OUT, "framename %s\n", wls->framename);
                     }
               if(strcasecmp(str, "AskForPublicIdentifierURI-FQDN") == 0)
                     {
                         str = strtok_r(NULL, ",", &pcmdStr);
                wls->AskForPublicIdentifierURI_FQDN = atoi(str);
                         DPRINT_INFO(WFA_OUT, "AskForPublicIdentifierURI_FQDN %d\n",
             wls->AskForPublicIdentifierURI_FQDN);
                     }
                       }
             }*/
        }
    } /* for */

    wfaEncodeTLV(WFA_STA_DEV_SEND_FRAME_TLV, sizeof(dutCommand_t), (BYTE *)cmd, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaExecAction(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaExecAction_t *execAction = (caStaExecAction_t *)(aBuf + sizeof(wfaTLV));

    DPRINT_INFO(WFA_OUT, "This is a StaExec commands\n");

    memset(aBuf, 0, *aLen);
    memset(execAction, 0, sizeof(caStaExecAction_t));
    char *str;

    for (;;)
    {
        str = strtok_r(pcmdStr, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(execAction->intf, str, 15);
        }
        else if (strcasecmp(str, "destmac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(execAction->destmac, str);
            printf("destmac: %s\n", str);
        }
        else if (strcasecmp(str, "trigger") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(execAction->trigger, str);
            printf("trigger: %s\n", str);
        }
        else if (strcasecmp(str, "BurstsExponent") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            execAction->BurstsExponent = atoi(str);
            printf("BurstsExponent: %d\n", execAction->BurstsExponent);
        }
        else if (strcasecmp(str, "asap") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            execAction->asap = atoi(str);
            printf("asap: %d\n", execAction->asap);
        }
        else if (strcasecmp(str, "FormatBwFTM") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            execAction->FormatBwFTM = atoi(str);
            printf("FormatBwFTM: %d\n", execAction->FormatBwFTM);
        }
        else if (strcasecmp(str, "askForLocCivic") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            execAction->askForLocCivic = atoi(str);
            printf("askForLocCivic: %d\n", execAction->askForLocCivic);
        }
        else if (strcasecmp(str, "askForLCI") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            execAction->askForLCI = atoi(str);
            printf("askForLCI: %d\n", execAction->askForLCI);
        }
    }

    wfaEncodeTLV(WFA_STA_EXEC_ACTION_TLV, sizeof(caStaExecAction_t), (BYTE *)execAction, aBuf);

    *aLen = 4 + sizeof(caStaExecAction_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaTestBedCmd(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *info = (dutCommand_t *)(aBuf + sizeof(wfaTLV));

    DPRINT_INFO(WFA_OUT, "This is a TestBed Station Command ONLY\n");

    wfaEncodeTLV(WFA_STA_SEND_NEIGREQ_TLV, sizeof(dutCommand_t), (BYTE *)info, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return WFA_SUCCESS;
}

#ifdef WFA_STA_TB
int xcCmdProcStaPresetTestParameters(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaPresetParameters_t *presetTestParams = (caStaPresetParameters_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    char *tstr1, *tstr2;

    // caStaPresetParameters_t initParams = { "0", 0, 0, 0x00, 0x0000, 0x00, 0x0000, 0x00, 0, 0x00, 0, 0xFF};

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memset(presetTestParams, 0, sizeof(caStaPresetParameters_t));

    // memcpy(presetTestParams, &initParams, sizeof(caStaPresetParameters_t));

    for (;;)
    {
        str = strtok_r(pcmdStr, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(presetTestParams->intf, str, 15);
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("modeis %s\n", str);

            if (strcasecmp(str, "11b") == 0 || strcasecmp(str, "b") == 0)
                presetTestParams->wirelessMode = eModeB;
            else if (strcasecmp(str, "11g") == 0 || strcasecmp(str, "g") == 0 || strcasecmp(str, "bg") == 0)
                presetTestParams->wirelessMode = eModeBG;
            else if (strcasecmp(str, "11a") == 0 || strcasecmp(str, "a") == 0)
                presetTestParams->wirelessMode = eModeA;
            else if (strcasecmp(str, "11abg") == 0 || strcasecmp(str, "abg") == 0)
                presetTestParams->wirelessMode = eModeABG;
            else if (strcasecmp(str, "11na") == 0)
                presetTestParams->wirelessMode = eModeAN;
            else if (strcasecmp(str, "11ng") == 0)
                presetTestParams->wirelessMode = eModeGN;
            else if (strcasecmp(str, "11nl") == 0)
                presetTestParams->wirelessMode = eModeNL; // n+abg
            else if (strcasecmp(str, "11ac") == 0)
            {
                presetTestParams->wirelessMode = eModeAC;
                presetTestParams->modeFlag     = 1;
            }
            else if (strcasecmp(str, "11ax") == 0)
            {
                presetTestParams->wirelessMode = eModeHE;
                presetTestParams->modeFlag     = 1;
            }

            printf("\nSetting Mode as-------------- %d-------------\n", presetTestParams->wirelessMode);
        }

        else if (strcasecmp(str, "Roaming") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Roaming_Flag = 1;
            if (strcasecmp(str, "Enable") == 0)
                presetTestParams->Roaming = 1;
            else if (strcasecmp(str, "Disable") == 0)
                presetTestParams->Roaming = 0;
        }
        else if (strcasecmp(str, "Ch_Op_Class") == 0)
        {
            str                                = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Ch_Op_Class_Flag = 1;
            presetTestParams->Ch_Op_Class      = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Reason_Code") == 0)
        {
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Ch_Reason_Code_Flag = 1;
            presetTestParams->Ch_Reason_Code      = atoi(str);
        }

        else if (strcasecmp(str, "Cellular_Data_Cap") == 0)
        {
            str                                      = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Cellular_Data_Cap_Flag = 1;
            presetTestParams->Cellular_Data_Cap      = atoi(str);
        }

        else if (strcasecmp(str, "Assoc_Disallow") == 0)
        {
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Assoc_Disallow_Flag = 1;
            if (strcasecmp(str, "Enable") == 0)
                presetTestParams->Assoc_Disallow = 1;
            else if (strcasecmp(str, "Disable") == 0)
                presetTestParams->Assoc_Disallow = 0;
        }
        else if (strcasecmp(str, "BSS_Transition") == 0)
        {
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->BSS_Transition_Flag = 1;
            if (strcasecmp(str, "Enable") == 0)
                presetTestParams->BSS_Transition = 1;
            else if (strcasecmp(str, "Reject") == 0)
                presetTestParams->BSS_Transition = 0;
        }
        else if (strcasecmp(str, "Ch_Pref_Num") == 0)
        {
            str                                = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Ch_Pref_Num_Flag = 1;
            presetTestParams->Ch_Pref_Num      = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Pref") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->Ch_Pref_Flag = 1;
            presetTestParams->Ch_Pref      = atoi(str);
        }

        else if (strcasecmp(str, "powersave") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("powersave is %s\n", str);
            if (strcasecmp(str, "on") == 0 || strcasecmp(str, "pspoll") == 0)
                presetTestParams->legacyPowerSave = 1;
            else if (strcasecmp(str, "fast") == 0)
                presetTestParams->legacyPowerSave = 2;
            else if (strcasecmp(str, "psnonpoll") == 0)
                presetTestParams->legacyPowerSave = 3;
            else
                presetTestParams->legacyPowerSave = 0;

            presetTestParams->psFlag = 1;
            printf("\nSetting legacyPowerSave as %d\n", presetTestParams->legacyPowerSave);
        }
        else if (strcasecmp(str, "wmm") == 0)
        {
            presetTestParams->wmmFlag = 1;
            str                       = strtok_r(NULL, ",", &pcmdStr);
            printf("wmm is %s\n", str);

            if (strcasecmp(str, "on") == 0)
                presetTestParams->wmmState = 1;
            else if (strcasecmp(str, "off") == 0)
                presetTestParams->wmmState = 0;
        }
        else if (strcasecmp(str, "noack") == 0)
        {
            /* uncomment and use it char *ackpol; */
            char *setvalues = strtok_r(NULL, ",", &pcmdStr);
            //          int ackpolcnt = 0;
            if (setvalues != NULL)
            {
                /* BE */
                /* str=strtok_r(NULL, ":", &setvalues);
                if(str != NULL)
                {
                    if(strcasecmp(str, "enable") == 0)
                       presetTestParams->noack_be = 2;
                    else if(strcasecmp(str, "disable") == 0)
                       presetTestParams->noack_be = 1;
                 }*/
                /* BK */
                /* str=strtok_r(NULL, ":", &setvalues);
                   if(str != NULL)
                   {
                      if(strcasecmp(str, "enable") == 0)
                         presetTestParams->noack_bk = 2;
                      else if(strcasecmp(str, "disable") == 0)
                         presetTestParams->noack_bk = 1;
  }*/
                /* VI */
                /* str=strtok_r(NULL, ":", &setvalues);
                if(str != NULL)
                {
                                  if(strcasecmp(str, "enable") == 0)
                                      presetTestParams->noack_vi = 2;
                                  else if(strcasecmp(str, "disable") == 0)
                                      presetTestParams->noack_vi = 1;
                              }*/
                /* VO */
                /*  str=strtok_r(NULL, ":", &setvalues);
                if(str != NULL)
                {
                    if(strcasecmp(str, "enable") == 0)
                       presetTestParams->noack_vo = 2;
                    else if(strcasecmp(str, "disable") == 0)
                       presetTestParams->noack_vo = 1;
                }*/
            }
        }
        else if (strcasecmp(str, "ht") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "on") == 0)
            {
                presetTestParams->ht = 1;
            }
            else
            {
                presetTestParams->ht = 0;
            }
        }
        else if (strcasecmp(str, "reset") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "11n") == 0)
            {
                presetTestParams->reset = eResetProg11n;
                printf("reset to %s\n", str);
            }
        }
        else if (strcasecmp(str, "ft_oa") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->ftoa = eEnable;
                printf("ft_oa enabled\n");
            }
            else
            {
                presetTestParams->ftoa = eDisable;
            }
            presetTestParams->ftoa_flag = 1;
        }
        else if (strcasecmp(str, "ft_ds") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->ftds = eEnable;
                printf("ft_ds enabled\n");
            }
            else
            {
                presetTestParams->ftds = eDisable;
            }
        }
        else if (strcasecmp(str, "active_scan") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->activescan = eEnable;
                printf("active scan enabled\n");
            }
            else
            {
                presetTestParams->activescan = eDisable;
            }
        }
#if 0
        else if(strcasecmp(str, "ignoreChswitchProhibit") == 0)
        {
           str = strtok_r(NULL, ",", &pcmdStr);
           if(strcasecmp(str, "Enabled") == 0)
           {
              presetTestParams->ignChSwitchProh = eEnable;
           }
           else
           {
              presetTestParams->ignChSwitchProh = eDisable;
           }
        }
#endif
        else if (strcasecmp(str, "tdls") == 0)
        {
            presetTestParams->tdlsFlag = 1;
            str                        = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enabled") == 0)
            {
                presetTestParams->tdls = eEnable;
            }
            else
            {
                presetTestParams->tdls = eDisable;
            }
        }
        else if (strcasecmp(str, "tdlsmode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Default") == 0)
            {
                presetTestParams->tdlsMode = eDef;
            }
            else if (strcasecmp(str, "HiLoMac") == 0)
            {
                presetTestParams->tdlsMode = eHiLoMac;
            }
            else if (strcasecmp(str, "ExistLink") == 0)
            {
                presetTestParams->tdlsMode = eExistLink;
            }
            else if (strcasecmp(str, "APProhibit") == 0)
            {
                presetTestParams->tdlsMode = eAPProhibit;
            }
            else if (strcasecmp(str, "WeakSecurity") == 0)
            {
                presetTestParams->tdlsMode = eWeakSec;
            }
            else if (strcasecmp(str, "IgnoreChswitchProhibit") == 0)
            {
                presetTestParams->tdlsMode = eIgnChnlSWProh;
            }
        }
        else if (strcasecmp(str, "wfddevtype") == 0)
        {
            presetTestParams->wfdDevTypeFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "source") == 0)
            {
                presetTestParams->wfdDevType = eSource;
            }
            else if (strcasecmp(str, "p-sink") == 0)
            {
                presetTestParams->wfdDevType = ePSink;
            }
            else if (strcasecmp(str, "s-sink") == 0)
            {
                presetTestParams->wfdDevType = eSSink;
            }
            else if (strcasecmp(str, "dual") == 0)
            {
                presetTestParams->wfdDevType = eDual;
            }
        }
        else if (strcasecmp(str, "uibc_gen") == 0)
        {
            presetTestParams->wfdUibcGenFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdUibcGen = eEnable;
            }
            else
            {
                presetTestParams->wfdUibcGen = eDisable;
            }
        }
        else if (strcasecmp(str, "uibc_hid") == 0)
        {
            presetTestParams->wfdUibcHidFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdUibcHid = eEnable;
            }
            else
            {
                presetTestParams->wfdUibcHid = eDisable;
            }
        }
        else if (strcasecmp(str, "ui_input") == 0)
        {
            char *uilist;
            presetTestParams->wfdUiInputFlag = 1;

            uilist                        = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->wfdUiInputs = 0;

            for (;;)
            {
                str = strtok_r(uilist, " ", &uilist);
                if (str == NULL || str[0] == '\0')
                    break;

                printf("\n The UI input is : %s", str);

                if (strcasecmp(str, "keyboard") == 0)
                {
                    presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs] = eKeyBoard;
                }
                else if (strcasecmp(str, "mouse") == 0)
                {
                    presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs] = eMouse;
                }
                /*   else if(strcasecmp(str, "bt") == 0)
                   {
                   presetTestParams->wfdUiInput= eMouse;
                   }
                   else if(strcasecmp(str, "joystick") == 0)
                   {
                   presetTestParams->wfdUiInput= eJoyStick;
                   }
                   else if(strcasecmp(str, "singletouchmouse") == 0)
                   {
                   presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs]= eSingleTouch;
                   }
                   else if(strcasecmp(str, "multitouchmouse") == 0)
                   {
                   presetTestParams->wfdUiInput[presetTestParams->wfdUiInputs]= eMultiTouch;
                   }*/

                presetTestParams->wfdUiInputs++;
            }
        }
        else if (strcasecmp(str, "hdcp") == 0)
        {
            presetTestParams->wfdHdcpFlag = 1;
            str                           = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdHdcp = eEnable;
            }
            else
            {
                presetTestParams->wfdHdcp = eDisable;
            }
        }
        else if (strcasecmp(str, "frameskip") == 0)
        {
            presetTestParams->wfdFrameSkipFlag = 1;
            str                                = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdFrameSkip = eEnable;
            }
            else
            {
                presetTestParams->wfdFrameSkip = eDisable;
            }
        }
        else if (strcasecmp(str, "avchange") == 0)
        {
            presetTestParams->wfdAvChangeFlag = 1;
            str                               = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdAvChange = eEnable;
            }
            else
            {
                presetTestParams->wfdAvChange = eDisable;
            }
        }
        else if (strcasecmp(str, "standby") == 0)
        {
            presetTestParams->wfdStandByFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdStandBy = eEnable;
            }
            else
            {
                presetTestParams->wfdStandBy = eDisable;
            }
        }
        else if (strcasecmp(str, "inputcontent") == 0)
        {
            presetTestParams->wfdInVideoFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Protected") == 0)
            {
                presetTestParams->wfdInVideo = eProtected;
            }
            else if (strcasecmp(str, "Unprotected") == 0)
            {
                presetTestParams->wfdInVideo = eUnprotected;
            }
            //  else if(strcasecmp(str, "ProtectedAudio") == 0)
            //  {
            //     presetTestParams->wfdInVideo= eProtectedAudio;
            //  }
            else if (strcasecmp(str, "ProtectedVideoOnly") == 0)
            {
                presetTestParams->wfdInVideo = eProtectedVideoOnly;
            }
            //  else if(strcasecmp(str, "UnprotectedAudio") == 0)
            //  {
            //     presetTestParams->wfdInVideo= eUnProtectedAudio;
            //  }
        }

        else if (strcasecmp(str, "videoformat") == 0)
        {
            int temp1;
            char *videolist;
            presetTestParams->wfdVideoFmatFlag = 1;

            videolist                            = strtok_r(NULL, ",", &pcmdStr);
            presetTestParams->wfdInputVideoFmats = 0;

            for (;;)
            {
                str = strtok_r(videolist, " ", &videolist);
                if (str == NULL || str[0] == '\0')
                    break;

                printf("\n The Video format is : %s", str);

                tstr1 = strtok_r(str, "-", &str);
                tstr2 = strtok_r(str, "-", &str);

                temp1 = atoi(tstr2);
                printf("\n The Video format is : %s****%d*****", tstr1, temp1);

                if (strcasecmp(tstr1, "cea") == 0)
                {
                    presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats] = eCEA + 1 + temp1;
                }
                else if (strcasecmp(tstr1, "vesa") == 0)
                {
                    presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats] = eVesa + 1 + temp1;
                }
                else
                {
                    presetTestParams->wfdVideoFmt[presetTestParams->wfdInputVideoFmats] = eHH + 1 + temp1;
                }
                presetTestParams->wfdInputVideoFmats++;
            }
        }
        else if (strcasecmp(str, "AudioFormat") == 0)
        {
            presetTestParams->wfdAudioFmatFlag = 1;
            str                                = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Mandatory") == 0)
            {
                presetTestParams->wfdAudioFmt = eMandatoryAudioMode;
            }
            else
            {
                presetTestParams->wfdAudioFmt = eDefaultAudioMode;
            }
        }

        else if (strcasecmp(str, "i2c") == 0)
        {
            presetTestParams->wfdI2cFlag = 1;
            str                          = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdI2c = eEnable;
            }
            else
            {
                presetTestParams->wfdI2c = eDisable;
            }
        }
        else if (strcasecmp(str, "videorecovery") == 0)
        {
            presetTestParams->wfdVideoRecoveryFlag = 1;
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdVideoRecovery = eEnable;
            }
            else
            {
                presetTestParams->wfdVideoRecovery = eDisable;
            }
        }
        else if (strcasecmp(str, "PrefDisplay") == 0)
        {
            presetTestParams->wfdPrefDisplayFlag = 1;
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdPrefDisplay = eEnable;
            }
            else
            {
                presetTestParams->wfdPrefDisplay = eDisable;
            }
        }
        else if (strcasecmp(str, "ServiceDiscovery") == 0)
        {
            presetTestParams->wfdServiceDiscoveryFlag = 1;
            str                                       = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdServiceDiscovery = eEnable;
            }
            else
            {
                presetTestParams->wfdServiceDiscovery = eDisable;
            }
        }
        else if (strcasecmp(str, "3dVideo") == 0)
        {
            presetTestParams->wfd3dVideoFlag = 1;
            str                              = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfd3dVideo = eEnable;
            }
            else
            {
                presetTestParams->wfd3dVideo = eDisable;
            }
        }
        else if (strcasecmp(str, "MultiTxStream") == 0)
        {
            presetTestParams->wfdMultiTxStreamFlag = 1;
            str                                    = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdMultiTxStream = eEnable;
            }
            else
            {
                presetTestParams->wfdMultiTxStream = eDisable;
            }
        }
        else if (strcasecmp(str, "TimeSync") == 0)
        {
            presetTestParams->wfdTimeSyncFlag = 1;
            str                               = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdTimeSync = eEnable;
            }
            else
            {
                presetTestParams->wfdTimeSync = eDisable;
            }
        }
        else if (strcasecmp(str, "EDID") == 0)
        {
            presetTestParams->wfdEDIDFlag = 1;
            str                           = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdEDID = eEnable;
            }
            else
            {
                presetTestParams->wfdEDID = eDisable;
            }
        }
        else if (strcasecmp(str, "UIBC_Prepare") == 0)
        {
            presetTestParams->wfdUIBCPrepareFlag = 1;
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdUIBCPrepare = eEnable;
            }
            else
            {
                presetTestParams->wfdUIBCPrepare = eDisable;
            }
        }
        else if (strcasecmp(str, "OptionalFeature") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "DisableAll") == 0)
            {
                presetTestParams->wfdOptionalFeatureFlag = eEnable;
            }
            else
            {
                presetTestParams->wfdOptionalFeatureFlag = eDisable;
            }
        }
        else if (strcasecmp(str, "SessionAvailability") == 0)
        {
            presetTestParams->wfdSessionAvailFlag = 1;
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdSessionAvail = eEnable;
            }
            else
            {
                presetTestParams->wfdSessionAvail = eDisable;
            }
        }
        else if (strcasecmp(str, "DeviceDiscoverability") == 0)
        {
            presetTestParams->wfdDeviceDiscoverabilityFlag = 1;
            str                                            = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdDeviceDiscoverability = eEnable;
            }
            else
            {
                presetTestParams->wfdDeviceDiscoverability = eDisable;
            }
        }
        else if (strcasecmp(str, "program") == 0)
        {
            presetTestParams->programFlag = 1;
            str                           = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "PMF") == 0)
            {
                presetTestParams->program = PROG_TYPE_PMF;
            }
            else if (strcasecmp(str, "General") == 0)
            {
                presetTestParams->program = PROG_TYPE_GEN;
            }
            else if (strcasecmp(str, "TDLS") == 0)
            {
                presetTestParams->program = PROG_TYPE_TDLS;
            }
            else if (strcasecmp(str, "VOE") == 0)
            {
                presetTestParams->program = PROG_TYPE_VENT;
            }
            else if (strcasecmp(str, "WFD") == 0)
            {
                presetTestParams->program = PROG_TYPE_WFD;
            }
            else if (strcasecmp(str, "HS2-R2") == 0 || strcasecmp(str, "HS2") == 0)
            {
                presetTestParams->program = PROG_TYPE_HS2;
            }
            else if (strcasecmp(str, "MBO") == 0)
            {
                presetTestParams->program = PROG_TYPE_MBO;
            }
            else if (strcasecmp(str, "HE") == 0)
            {
                presetTestParams->program = PROG_TYPE_HE;
            }
        }
        else if (strcasecmp(str, "CoupledCap") == 0)
        {
            presetTestParams->wfdCoupledCapFlag = 1;
            str                                 = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enable") == 0)
            {
                presetTestParams->wfdCoupledCap = eEnable;
            }
            else
            {
                presetTestParams->wfdCoupledCap = eDisable;
            }
        }
        else if (strcasecmp(str, "ppsmoID") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("Inside ppsmoID, str=%s\n", str);
            sscanf(str, "ID%d", &(presetTestParams->wfdPpsMoId));
            printf("ID=%d\n", presetTestParams->wfdPpsMoId);
        }
        else if (strcasecmp(str, "FileType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("FileType, str=%s\n", str);
            strncpy(presetTestParams->fileType, str, 10);
            printf("presetTestParams->fileType is %s\n", presetTestParams->fileType);
        }
        else if (strcasecmp(str, "FileName") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("FileName, str=%s\n", str);
            strncpy(presetTestParams->fileName, str, 30);
            printf("presetTestParams->fileName is %s\n", presetTestParams->fileName);
        }
        else if (strcasecmp(str, "FilePath") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("FilePath, str=%s\n", str);
            strncpy(presetTestParams->filePath, str, 100);
            printf("presetTestParams->filePath is %s\n", presetTestParams->filePath);
        }
        else if (strcasecmp(str, "ProvisioningProto") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("ProvisioningProto, str=%s\n", str);
            strncpy(presetTestParams->provisioningProto, str, 10);
            printf("presetTestParams->provisioningProto is %s\n", presetTestParams->provisioningProto);
        }
    }

    wfaEncodeTLV(WFA_STA_PRESET_PARAMETERS_TLV, sizeof(caStaPresetParameters_t), (BYTE *)presetTestParams, aBuf);

    *aLen = 4 + sizeof(caStaPresetParameters_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaResetDefault_t *reset = (caStaResetDefault_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(reset->intf, str, 15);
        }
        else if (strcasecmp(str, "prog") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(reset->prog, str, 8);
        }
        else if (strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            memset(reset->type, 0, sizeof(reset->type));
            strncpy(reset->type, str, sizeof(reset->type));
            if (!(strcasecmp(reset->type, "testbed")))
            {
                reset->testbed = 1;
                printf("\nThe reset type has been set to %s and tesbed_flag is %d", reset->type, reset->testbed);
            }
            else
                printf("\n the reset type is for DUT");
        }
    }
    wfaEncodeTLV(WFA_STA_RESET_DEFAULT_TLV, sizeof(caStaResetDefault_t), (BYTE *)reset, aBuf);
    *aLen = 4 + sizeof(caStaResetDefault_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetRadio(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str;
    dutCommand_t *cmd   = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    caStaSetRadio_t *sr = &cmd->cmdsu.sr;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(cmd->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "off") == 0)
            {
                sr->mode = WFA_OFF;
            }
            else
            {
                sr->mode = WFA_ON;
            }
        }
    }

    return WFA_SUCCESS;
}

int fSetWirelessProg11n(char *pcmdStr, caStaSetWireless_t *swp11n)
{
    char *str;
    struct setWireless11n *prog11n = (struct setWireless11n *)&swp11n->progs.cert11n;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "40_intolerant") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            prog11n->_40_intolerant = wfaStandardBoolParsing(str);
            if (prog11n->_40_intolerant < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid _40_intolerant Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n _40_intolerant -%i- \n", prog11n->_40_intolerant);
        }
        else if (strcasecmp(str, "addba_reject") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            prog11n->addba_reject = wfaStandardBoolParsing(str);
            if (prog11n->addba_reject < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid addba_reject Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n addba_reject -%i- \n", prog11n->addba_reject);
        }
        if (strcasecmp(str, "ampdu") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            prog11n->ampdu = wfaStandardBoolParsing(str);
            if (prog11n->ampdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid AMPDU Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n AMPDU -%i- \n", prog11n->ampdu);
        }
        else if (strcasecmp(str, "amsdu") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            prog11n->amsdu = wfaStandardBoolParsing(str);
            if (prog11n->amsdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid amsdu Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n amsdu -%i- \n", prog11n->amsdu);
        }
        else if (strcasecmp(str, "greenfield") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            prog11n->greenfield = wfaStandardBoolParsing(str);
            if (prog11n->greenfield < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid greenfield Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n greenfield -%i- \n", prog11n->greenfield);
        }
        else if (strcasecmp(str, "sgi20") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            prog11n->sgi20 = wfaStandardBoolParsing(str);
            if (prog11n->sgi20 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid sgi20 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n sgi20 -%i- \n", prog11n->sgi20);
        }
        else if (strcasecmp(str, "stbc_rx") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            prog11n->stbc_rx = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n stbc rx -%d- \n", prog11n->stbc_rx);
        }
        else if (strcasecmp(str, "smps") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            prog11n->smps = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n smps  -%d- \n", prog11n->smps);
        }
        else if (strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(prog11n->width, str, 7);
            DPRINT_INFO(WFA_OUT, "\n width -%s- \n", prog11n->width);
        }
        else if (strcasecmp(str, "mcs_fixedrate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(prog11n->mcs_fixedrate, str, 3);
            DPRINT_INFO(WFA_OUT, "\n mcs fixedrate -%s- \n", prog11n->mcs_fixedrate);
        }
        else if (strcasecmp(str, "mcs32") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            prog11n->mcs32 = wfaStandardBoolParsing(str);
            if (prog11n->mcs32 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid mcs32 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n mcs32 -%i- \n", prog11n->mcs32);
        }
        else if (strcasecmp(str, "rifs_test") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            prog11n->rifs_test = wfaStandardBoolParsing(str);
            if (prog11n->rifs_test < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid rifs_test Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n rifs_test -%i- \n", prog11n->rifs_test);
        }
        else if (strcasecmp(str, "txsp_stream") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            prog11n->txsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n txsp_stream -%d- \n", prog11n->txsp_stream);
        }
        else if (strcasecmp(str, "rxsp_stream") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            prog11n->rxsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n rxsp_stream -%d- \n", prog11n->rxsp_stream);
        }
        else
        {
            DPRINT_INFO(WFA_OUT, "unknown parameter %s\n", str);
        }
    }

    return WFA_SUCCESS;
}

int fSetWirelessProgVHT5G(char *pcmdStr, caStaSetWireless_t *swpvht)
{
    char *str;
    struct setWirelessVHT5G *progVHT = (struct setWirelessVHT5G *)&swpvht->progs.vht5g;
    int i                            = 0;

    memset(progVHT, 0, sizeof(struct setWirelessVHT5G));

    printf("\nIn fSetWirelessProgVHT5G: pcmdStr=%s\n", pcmdStr);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        printf("i = %d, str=%s\n", i, str);
        if (str == NULL || str[0] == '\0')
            break;
        printf("\n==> str - %s\n", str);
        if (strcasecmp(str, "40_intolerant") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            progVHT->_40_intolerant = wfaStandardBoolParsing(str);
            if (progVHT->_40_intolerant < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid _40_intolerant Value %s\n", str);
                return WFA_FAILURE;
            }
            progVHT->_40_intolerant_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n _40_intolerant -%i- \n", progVHT->_40_intolerant);
        }
        else if (strcasecmp(str, "addba_reject") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            progVHT->addba_reject = wfaStandardBoolParsing(str);
            if (progVHT->addba_reject < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid addba_reject Value %s\n", str);
                return WFA_FAILURE;
            }
            progVHT->addba_reject_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n addba_reject -%i- \n", progVHT->addba_reject);
        }
        else if (strcasecmp(str, "ampdu") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            progVHT->ampdu = wfaStandardBoolParsing(str);
            if (progVHT->ampdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid AMPDU Value %s\n", str);
                return WFA_FAILURE;
            }
            progVHT->ampdu_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n AMPDU -%i- \n", progVHT->ampdu);
        }
        else if (strcasecmp(str, "amsdu") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            progVHT->amsdu = wfaStandardBoolParsing(str);
            if (progVHT->amsdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid amsdu Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n amsdu -%i- \n", progVHT->amsdu);
            progVHT->amsdu_flag = 1;
        }
        else if (strcasecmp(str, "greenfield") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            progVHT->greenfield = wfaStandardBoolParsing(str);
            if (progVHT->greenfield < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid greenfield Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n greenfield -%i- \n", progVHT->greenfield);
            progVHT->greenfield_flag = 1;
        }
        else if (strcasecmp(str, "sgi20") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            progVHT->sgi20 = wfaStandardBoolParsing(str);
            if (progVHT->sgi20 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid sgi20 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n sgi20 -%i- \n", progVHT->sgi20);
            progVHT->sgi20_flag = 1;
        }
        else if (strcasecmp(str, "stbc_rx") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            progVHT->stbc_rx = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n stbc rx -%d- \n", progVHT->stbc_rx);
            progVHT->stbc_rx_flag = 1;
        }
        else if (strcasecmp(str, "smps") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            progVHT->smps = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n smps  -%d- \n", progVHT->smps);
            progVHT->smps_flag = 1;
        }
        else if (strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progVHT->width, str, 7);
            DPRINT_INFO(WFA_OUT, "\n width -%s- \n", progVHT->width);
            progVHT->width_flag = 1;
        }
        else if (strcasecmp(str, "mcs32") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            progVHT->mcs32 = wfaStandardBoolParsing(str);
            if (progVHT->mcs32 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid mcs32 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n mcs32 -%i- \n", progVHT->mcs32);
            progVHT->mcs32_flag = 1;
        }
        else if (strcasecmp(str, "rifs_test") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            progVHT->rifs_test = wfaStandardBoolParsing(str);
            if (progVHT->rifs_test < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid rifs_test Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n rifs_test -%i- \n", progVHT->rifs_test);
            progVHT->rifs_test_flag = 1;
        }
        else if (strcasecmp(str, "txsp_stream") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            progVHT->txsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n txsp_stream -%d- \n", progVHT->txsp_stream);
            progVHT->txsp_stream_flag = 1;
        }
        else if (strcasecmp(str, "rxsp_stream") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            progVHT->rxsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n rxsp_stream -%d- \n", progVHT->rxsp_stream);
            progVHT->rxsp_stream_flag = 1;
        }
        else if (strcasecmp(str, "txbf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                progVHT->txBF = WFA_ENABLED;
            else
                progVHT->txBF = WFA_DISABLED;
            progVHT->txBF_flag = 1;
        }
        else if (strcasecmp(str, "ldpc") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                progVHT->ldpc = WFA_ENABLED;
            else
                progVHT->ldpc = WFA_DISABLED;
            progVHT->ldpc_flag = 1;
        }
        else if (strcasecmp(str, "opt_md_notif_ie") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progVHT->optMNotifIE, str, 7);
            progVHT->optMNotifIE_flag = 1;
        }
        else if (strcasecmp(str, "nss_mcs_cap") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progVHT->nssMCSCap, str, 7);
            progVHT->nssMCSCap_flag = 1;
            printf("sta got nss_mcs_cap para:%s\n", progVHT->nssMCSCap);
        }
        else if (strcasecmp(str, "nss_mcs_opt") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progVHT->nssMCSOpt, str, 7);
            progVHT->nssMCSOpt_flag = 1;
            printf("sta got nss_mcs_opt para:%s\n", progVHT->nssMCSOpt);
        }
        else if (strcasecmp(str, "sgi80") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            progVHT->sgi80      = wfaStandardBoolParsing(str);
            progVHT->sgi80_flag = 1;
        }
        else if (strcasecmp(str, "zero_crc") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            progVHT->zero_crc      = wfaStandardBoolParsing(str);
            progVHT->zero_crc_flag = 1;
        }
        else if (strcasecmp(str, "BW_SGNL") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            progVHT->bw_signal      = !strcasecmp(str, "enable");
            progVHT->bw_signal_flag = 1;
        }
        else if (strcasecmp(str, "DYN_BW_SGNL") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            progVHT->dyn_bw_signal      = !strcasecmp(str, "enable");
            progVHT->dyn_bw_signal_flag = 1;
        }
        else if (strcasecmp(str, "vht_tkip") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            progVHT->vht_tkip      = wfaStandardBoolParsing(str);
            progVHT->vht_tkip_flag = 1;
        }
        else
        {
            DPRINT_INFO(WFA_OUT, "unknown vht parameter %s\n", str);
        }
    }

    return WFA_SUCCESS;
}

/* Divesh: HE set_wireless implementation */

int fSetWirelessProgHE(char *pcmdStr, caStaSetWireless_t *swphe)
{
    char *str;
    struct setWirelessHE *progHE = (struct setWirelessHE *)&swphe->progs.he;
    int i                        = 0;

    memset(progHE, 0, sizeof(struct setWirelessHE));
    printf("\nIn fSetWirelessProgHE: pcmdStr=%s\n", pcmdStr);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        printf("i = %d, str=%s\n", i, str);
        if (str == NULL || str[0] == '\0')
            break;
        printf("\n==> str - %s\n", str);
        if (strcasecmp(str, "40_intolerant") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            progHE->_40_intolerant = wfaStandardBoolParsing(str);
            if (progHE->_40_intolerant < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid _40_intolerant Value %s\n", str);
                return WFA_FAILURE;
            }
            progHE->_40_intolerant_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n _40_intolerant -%i- \n", progHE->_40_intolerant);
        }
        else if (strcasecmp(str, "addba_reject") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            progHE->addba_reject = wfaStandardBoolParsing(str);
            if (progHE->addba_reject < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid addba_reject Value %s\n", str);
                return WFA_FAILURE;
            }
            progHE->addba_reject_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n addba_reject -%i- \n", progHE->addba_reject);
        }
        else if (strcasecmp(str, "ampdu") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            progHE->ampdu = wfaStandardBoolParsing(str);
            if (progHE->ampdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid AMPDU Value %s\n", str);
                return WFA_FAILURE;
            }
            progHE->ampdu_flag = 1;
            DPRINT_INFO(WFA_OUT, "\n AMPDU -%i- \n", progHE->ampdu);
        }
        else if (strcasecmp(str, "amsdu") == 0)
        {
            str           = strtok_r(NULL, ",", &pcmdStr);
            progHE->amsdu = wfaStandardBoolParsing(str);
            if (progHE->amsdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid amsdu Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n amsdu -%i- \n", progHE->amsdu);
            progHE->amsdu_flag = 1;
        }

        else if (strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->width, str, 7);
            DPRINT_INFO(WFA_OUT, "Divesh:Now set the chwidth in miscs.c");
            DPRINT_INFO(WFA_OUT, "\n width -%s- \n", progHE->width);
            progHE->width_flag = 1;
        }

        else if (strcasecmp(str, "mcs_fixedrate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->mcs_fixedrate, str, 7);
            DPRINT_INFO(WFA_OUT, "\nDivesh:Now set the MSC-Fixedrate to----%s----", progHE->mcs_fixedrate);

            progHE->mcs_fixedrate_flag = 1;
        }

        else if (strcasecmp(str, "ADDBAReq_BufSize") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->ADDBAReq_BufSize, str, 7);
            DPRINT_INFO(WFA_OUT, "\n addbareqbuff -%s- \n", progHE->ADDBAReq_BufSize);
            progHE->ADDBAReq_BufSize_flag = 1;
        }
        else if (strcasecmp(str, "ADDBAResp_BufSize") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->ADDBAResp_BufSize, str, 7);
            DPRINT_INFO(WFA_OUT, "\n addbarespbuff -%s- \n", progHE->ADDBAResp_BufSize);
            progHE->ADDBAResp_BufSize_flag = 1;
        }
        else if (strcasecmp(str, "BA_Recv_Status") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->BA_Recv_Status, str, 7);
            DPRINT_INFO(WFA_OUT, "\n BA_RECV_STATUS -%s- \n", progHE->BA_Recv_Status);
            progHE->BA_Recv_Status_flag = 1;
        }

        else if (strcasecmp(str, "OMControl") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            progHE->OMControl = wfaStandardBoolParsing(str);
            if (progHE->OMControl < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid OMControl Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n OMControl -%i- \n", progHE->OMControl);
            progHE->OMControl_flag = 1;
        }
        else if (strcasecmp(str, "UPH") == 0)
        {
            str         = strtok_r(NULL, ",", &pcmdStr);
            progHE->UPH = wfaStandardBoolParsing(str);
            if (progHE->UPH < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid UPH Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n UPH -%i- \n", progHE->OMControl);
            progHE->UPH_flag = 1;
        }
        else if (strcasecmp(str, "txsp_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->txsp_stream, str, 7);
            DPRINT_INFO(WFA_OUT, "Divesh:Now set the TX-NSS in miscs.c");
            DPRINT_INFO(WFA_OUT, "\n TX-NSS -%s- \n", progHE->txsp_stream);
            progHE->txsp_stream_flag = 1;
        }
        else if (strcasecmp(str, "rxsp_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(progHE->rxsp_stream, str, 7);
            DPRINT_INFO(WFA_OUT, "Divesh:Now set the RX-NSS in miscs.c");
            DPRINT_INFO(WFA_OUT, "\n RX-NSS -%s- \n", progHE->rxsp_stream);
            progHE->rxsp_stream_flag = 1;
        }

        else if (strcasecmp(str, "txbf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                progHE->txBF = WFA_ENABLED;
            else
                progHE->txBF = WFA_DISABLED;
            progHE->txBF_flag = 1;
        }
        else if (strcasecmp(str, "LDPC") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                progHE->ldpc = WFA_ENABLED;
            else
                progHE->ldpc = WFA_DISABLED;
            progHE->ldpc_flag = 1;
        }
        else if (strcasecmp(str, "BCC") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                progHE->bcc = WFA_ENABLED;
            else
                progHE->bcc = WFA_DISABLED;
            progHE->bcc_flag = 1;
        }
        else if (strcasecmp(str, "smps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "1") == 0)
                progHE->he_smps_flag = 1;
            else
                progHE->he_smps_flag = 0;
        }
        else if (strcasecmp(str, "he_smps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
            {
                progHE->HE_SMPS      = 1;
                progHE->he_smps_flag = 1;
            }
            else
            {
                progHE->HE_SMPS      = 0;
                progHE->he_smps_flag = 0;
            }
        }

        else
        {
            DPRINT_INFO(WFA_OUT, "unknown HE parameter %s\n", str);
        }
    }

    return WFA_SUCCESS;
}

int xcCmdProcStaSetWireless(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    //    caStaSetWireless_t initWirelessParams = {"wifi0","", "", 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,0xFFFF, 0xFFFF,
    //    "", "", 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    caStaSetWireless_t *staWirelessParams = (caStaSetWireless_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    int i = 0;

    DPRINT_INFO(WFA_OUT, "xcCmdProcStaSetWireless Starts...\n");

    memset(aBuf, 0, *aLen);
    //    memcpy(staWirelessParams, &initWirelessParams, sizeof(caStaSetWireless_t));

    printf("%s(): pcmdStr=%s\n", __func__, pcmdStr);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        printf("--i=%d, pcmdStr=%s, str=%s\n", i, pcmdStr, str);
        i++;
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWirelessParams->intf, str, 15);
        }
        else if (strcasecmp(str, "band") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staWirelessParams->band, str, 7);
            DPRINT_INFO(WFA_OUT, "\n Band -%s- \n", staWirelessParams->band);
        }
        else if (strcasecmp(str, "noack") == 0)
        {
            char *ackpol;
            int ackpolcnt   = 0;
            char *setvalues = strtok_r(NULL, ",", &pcmdStr);

            if (setvalues != NULL)
            {
                while ((ackpol = strtok_r(NULL, ":", &setvalues)) != NULL && ackpolcnt < 4)
                {
                    if (strcasecmp(str, "enable") == 0)
                        staWirelessParams->noAck[ackpolcnt] = 1;
                    else if (strcasecmp(str, "disable") == 0)
                        staWirelessParams->noAck[ackpolcnt] = 0;

                    ackpolcnt++;
                }
            }
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "11n") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_11N;
                fSetWirelessProg11n(pcmdStr, staWirelessParams);
            }
            else if (strcasecmp(str, "VHT") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_VHT5G;
                fSetWirelessProgVHT5G(pcmdStr, staWirelessParams);
            }
            else if (strcasecmp(str, "HE") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_HE;
                DPRINT_INFO(WFA_OUT, "Divesh:Entering fsetWirelessProgHE");
                fSetWirelessProgHE(pcmdStr, staWirelessParams);
            }
        }
        else if (strcasecmp(str, "prog") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "11n") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_11N;
                fSetWirelessProg11n(pcmdStr, staWirelessParams);
            }
            else if (strcasecmp(str, "VHT") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_VHT5G;
                fSetWirelessProgVHT5G(pcmdStr, staWirelessParams);
            }
            else if (strcasecmp(str, "HE") == 0)
            {
                staWirelessParams->prog = PROG_TYPE_HE;
                DPRINT_INFO(WFA_OUT, "Divesh:Entering fsetWirelessProgHE");
                fSetWirelessProgHE(pcmdStr, staWirelessParams);
            }
        }

        else
        {
            DPRINT_INFO(WFA_OUT, "unknown parameter -  %s\n", str);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_WIRELESS_TLV, sizeof(caStaSetWireless_t), (BYTE *)staWirelessParams, aBuf);
    *aLen = 4 + sizeof(caStaSetWireless_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaSendADDBA(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetSendADDBA_t *staSendADDBA = (caStaSetSendADDBA_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT, "xcCmdProcStaSendADDBA Starts...");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendADDBA->intf, str, 15);
        }
        else if (strcasecmp(str, "tid") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            staSendADDBA->tid = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n TID -%i- \n", staSendADDBA->tid);
        }
        else if (strcasecmp(str, "des_mac") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendADDBA->dest, str, WFA_MAC_ADDR_STR_LEN - 1);
            staSendADDBA->dest[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_SEND_ADDBA_TLV, sizeof(caStaSetSendADDBA_t), (BYTE *)staSendADDBA, aBuf);
    *aLen = 4 + sizeof(caStaSetSendADDBA_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSetRIFS(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSetRIFS_t *staSetRIFS = (caStaSetRIFS_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT, "xcCmdProcSetRIFS starts ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSetRIFS->intf, str, 15);
        }
        else if (strcasecmp(str, "action") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            staSetRIFS->action = wfaStandardBoolParsing(str);
            DPRINT_INFO(WFA_OUT, "\n TID -%i- \n", staSetRIFS->action);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_RIFS_TEST_TLV, sizeof(caStaSetRIFS_t), (BYTE *)staSetRIFS, aBuf);
    *aLen = 4 + sizeof(caStaSetRIFS_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSendCoExistMGMT(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaSendCoExistMGMT_t *staSendMGMT = (caStaSendCoExistMGMT_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT, "xcCmdProcSendCoExistMGMT starts ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendMGMT->intf, str, 15);
        }
        else if (strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendMGMT->type, str, 15);
        }
        else if (strcasecmp(str, "value") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staSendMGMT->value, str, 15);
        }
    }

    wfaEncodeTLV(WFA_STA_SEND_COEXIST_MGMT_TLV, sizeof(caStaSendCoExistMGMT_t), (BYTE *)staSendMGMT, aBuf);
    *aLen = 4 + sizeof(caStaSendCoExistMGMT_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaSet11n(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caSta11n_t *v11nParams = (caSta11n_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caSta11n_t init11nParams = {"wifi0", 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFFFF,
                                0xFFFF,  "",   "",   0xFF, 0xFF, 0xFF, 0xFF};

    DPRINT_INFO(WFA_OUT, "xcCmdProcStaSet11n Starts...");

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    memcpy(v11nParams, &init11nParams, sizeof(caSta11n_t));

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->intf, str, WFA_IF_NAME_LEN - 1);
            v11nParams->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }

        if (strcasecmp(str, "ampdu") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->ampdu = wfaStandardBoolParsing(str);
            if (v11nParams->ampdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid AMPDU Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n AMPDU -%i- \n", v11nParams->ampdu);
        }
        else if (strcasecmp(str, "40_intolerant") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->_40_intolerant = wfaStandardBoolParsing(str);
            if (v11nParams->_40_intolerant < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid _40_intolerant Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n _40_intolerant -%i- \n", v11nParams->_40_intolerant);
        }
        else if (strcasecmp(str, "sgi20") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->sgi20 = wfaStandardBoolParsing(str);
            if (v11nParams->sgi20 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid sgi20 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n sgi20 -%i- \n", v11nParams->sgi20);
        }
        else if (strcasecmp(str, "amsdu") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->amsdu = wfaStandardBoolParsing(str);
            if (v11nParams->amsdu < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid amsdu Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n amsdu -%i- \n", v11nParams->amsdu);
        }
        else if (strcasecmp(str, "addba_reject") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->addba_reject = wfaStandardBoolParsing(str);
            if (v11nParams->addba_reject < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid addba_reject Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n addba_reject -%i- \n", v11nParams->addba_reject);
        }
        else if (strcasecmp(str, "greenfield") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->greenfield = wfaStandardBoolParsing(str);
            if (v11nParams->greenfield < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid greenfield Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n greenfield -%i- \n", v11nParams->greenfield);
        }
        else if (strcasecmp(str, "mcs32") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->mcs32 = wfaStandardBoolParsing(str);
            if (v11nParams->mcs32 < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid mcs32 Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n mcs32 -%i- \n", v11nParams->mcs32);
        }
        else if (strcasecmp(str, "rifs_test") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->rifs_test = wfaStandardBoolParsing(str);
            if (v11nParams->rifs_test < 0)
            {
                DPRINT_INFO(WFA_OUT, "Invalid rifs_test Value %s\n", str);
                return WFA_FAILURE;
            }
            DPRINT_INFO(WFA_OUT, "\n rifs_test -%i- \n", v11nParams->rifs_test);
        }
        else if (strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->width, str, 7);
            DPRINT_INFO(WFA_OUT, "\n width -%s- \n", v11nParams->width);
        }
        else if (strcasecmp(str, "mcs_fixedrate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(v11nParams->mcs_fixedrate, str, 3);
            DPRINT_INFO(WFA_OUT, "\n mcs fixedrate -%s- \n", v11nParams->mcs_fixedrate);
        }
        else if (strcasecmp(str, "stbc_rx") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->stbc_rx = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n stbc rx -%d- \n", v11nParams->stbc_rx);
        }
        else if (strcasecmp(str, "smps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "dynamic") == 0)
            {
                v11nParams->smps = 0;
            }
            else if (strcasecmp(str, "static") == 0)
            {
                v11nParams->smps = 1;
            }
            else if (strcasecmp(str, "nolimit") == 0)
            {
                v11nParams->smps = 2;
            }
            DPRINT_INFO(WFA_OUT, "\n smps  -%d- \n", v11nParams->smps);
        }
        else if (strcasecmp(str, "txsp_stream") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->txsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n txsp_stream -%d- \n", v11nParams->txsp_stream);
        }
        else if (strcasecmp(str, "rxsp_stream") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            v11nParams->rxsp_stream = atoi(str);
            DPRINT_INFO(WFA_OUT, "\n rxsp_stream -%d- \n", v11nParams->rxsp_stream);
        }
    }

    wfaEncodeTLV(WFA_STA_SET_11N_TLV, sizeof(caSta11n_t), (BYTE *)v11nParams, aBuf);
    *aLen = 4 + sizeof(caSta11n_t);
    return WFA_SUCCESS;
}

#endif

enum
{
    SEC_CHOFFSET_20     = 0,
    SEC_CHOFFSET_40UP   = 1,
    SEC_CHOFFSET_40DOWN = 3,
};

int xcCmdProcStaSetRFeature(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaRFeat_t *rfeat = (caStaRFeat_t *)(aBuf + sizeof(wfaTLV));
    rfeatTDLS_t *tdls   = &rfeat->rfeaType.tdls;
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        //  printf("=> %s", str);
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->intf, str, 15);
            rfeat->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        if (strcasecmp(str, "prog") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->prog, str, 7);
            {
                if (!(strcasecmp((rfeat->prog), "HE")))
                    rfeat->prog_enum_name = PROG_TYPE_HE;
                if (BAND_24G == 1)
                {
                    rfeat->HE_BAND_24G = 1;
                    rfeat->HE_BAND_5G  = 0;
                    printf("The value of rfeature band is  %d \n\r", rfeat->HE_BAND_24G);
                }
                if (BAND_5G == 1)
                {
                    rfeat->HE_BAND_5G  = 1;
                    rfeat->HE_BAND_24G = 0;
                    printf("The value of rfeature band is  %d \n\r", rfeat->HE_BAND_5G);
                }
            }
        }
        else if (strcasecmp(str, "uapsd") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                rfeat->uapsd = eEnable;
            else
                rfeat->uapsd = eDisable;
        }
        else if (strcasecmp(str, "peer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->peer, str, 17);
        }
        else if (strcasecmp(str, "tpktimer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "enable") == 0)
                rfeat->tpktimer = eEnable;
            else
                rfeat->tpktimer = eDisable;
        }
        else if (strcasecmp(str, "nss_mcs_opt") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(rfeat->nss_mcs_opt, str);
            rfeat->nss_mcs_opt_flag = 1;
        }
        else if (strcasecmp(str, "ChSwitchMode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Initiate") == 0)
                tdls->chsw = eChanEnable;
            else if (strcasecmp(str, "Passive") == 0)
            {
                printf(" THIS SHOULD TRIGGER disable_cs 1");
                tdls->chsw = eChanDisable;
            }
            else if (strcasecmp(str, "RejReq") == 0)
                tdls->chsw = eRejectReq;
            else if (strcasecmp(str, "UnSolResp") == 0)
                tdls->chsw = eUnSolResp;
        }
        else if (strcasecmp(str, "OffChNum") == 0)
        {
            str            = strtok_r(NULL, ",", &pcmdStr);
            tdls->offchnum = atoi(str);
        }
        else if (strcasecmp(str, "SecChOffset") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "20") == 0)
                tdls->secChOffset = SEC_CHOFFSET_20;
            else if (strcasecmp(str, "40above") == 0)
                tdls->secChOffset = SEC_CHOFFSET_40UP;
            else if (strcasecmp(str, "40below") == 0)
                tdls->secChOffset = SEC_CHOFFSET_40DOWN;
        }

        else if (strcasecmp(str, "Nebor_Pref") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Nebor_Pref_Flag = 1;
            rfeat->Nebor_Pref      = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Pref") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Ch_Pref_Flag = 1;
            if (strcasecmp(str, "clear") == 0)
                rfeat->Ch_Pref = 0;
            else
                rfeat->Ch_Pref = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Pref_Num") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Ch_Pref_Num_Flag = 1;
            rfeat->Ch_Pref_Num      = atoi(str);
        }
        else if (strcasecmp(str, "Cellular_Data_Cap") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Cellular_Data_Cap_Flag = 1;
            rfeat->Cellular_Data_Cap      = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Op_Class") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Ch_Op_Class_Flag = 1;
            rfeat->Ch_Op_Class      = atoi(str);
        }
        else if (strcasecmp(str, "Ch_Reason_Code") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Ch_Reason_Code_Flag = 1;
            rfeat->Ch_Reason_Code      = atoi(str);
        }
        else if (strcasecmp(str, "NDPPagingInd") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            rfeat->NDPPagingInd_Flag = 1;
            rfeat->NDPPagingInd      = atoi(str);
        }
        else if (strcasecmp(str, "RespPMMode") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            rfeat->RespPMMode_Flag = 1;
            rfeat->RespPMMode      = atoi(str);
        }
        else if (strcasecmp(str, "NegotiationType") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            rfeat->NegotiationType_Flag = 1;
            rfeat->NegotiationType      = atoi(str);
        }
        else if (strcasecmp(str, "TWT_Setup") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            rfeat->TWT_Setup_Flag = 1;
            strncpy(rfeat->TWT_Setup, str, 9);
            printf("\nThe TWT_SETUP type is %s\n", rfeat->TWT_Setup);
        }
        else if (strcasecmp(str, "SetupCommand") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            rfeat->SetupCommand_Flag = 1;
            rfeat->SetupCommand      = atoi(str);
        }
        else if (strcasecmp(str, "TWT_Trigger") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            rfeat->TWT_Trigger_Flag = 1;
            rfeat->TWT_Trigger      = atoi(str);
        }
        else if (strcasecmp(str, "implicit") == 0)
        {
            str             = strtok_r(NULL, ",", &pcmdStr);
            rfeat->implicit = atoi(str);
        }
        else if (strcasecmp(str, "FlowType") == 0)
        {
            str             = strtok_r(NULL, ",", &pcmdStr);
            rfeat->FlowType = atoi(str);
        }
        else if (strcasecmp(str, "WakeIntervalExp") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            rfeat->WakeIntervalExp = atoi(str);
        }
        else if (strcasecmp(str, "Protection") == 0)
        {
            str               = strtok_r(NULL, ",", &pcmdStr);
            rfeat->Protection = atoi(str);
        }
        else if (strcasecmp(str, "NominalMinWakeDur") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            rfeat->NominalMinWakeDur = atoi(str);
        }
        else if (strcasecmp(str, "WakeIntervalMantissa") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            rfeat->WakeIntervalMantissa = atoi(str);
        }

        else if (strcasecmp(str, "TWT_Channel") == 0)
        {
            str                = strtok_r(NULL, ",", &pcmdStr);
            rfeat->TWT_Channel = atoi(str);
        }
        /* OM control */
        else if (strcasecmp(str, "transmitOMI") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            rfeat->transmitOMI_Flag = 1;
        }
        else if (strcasecmp(str, "OMCtrl_TxNSTS") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            rfeat->OMCtrl_TxNSTS = atoi(str);
        }
        else if (strcasecmp(str, "OMCtrl_ChnlWidth") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            rfeat->OMCtrl_ChnlWidth = atoi(str);
        }
        else if (strcasecmp(str, "OMCtrl_ULMUDisable") == 0)
        {
            str                       = strtok_r(NULL, ",", &pcmdStr);
            rfeat->OMCtrl_ULMUDisable = atoi(str);
        }
        else if (strcasecmp(str, "OMCtrl_ULMUDataDisable") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            rfeat->OMCtrl_ULMUDataDisable = atoi(str);
        }
        else if (strcasecmp(str, "LTF") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->LTF, str, 4);
            rfeat->LTF_Flag = 1;
        }
        else if (strcasecmp(str, "GI") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->GI, str, 4);
            rfeat->GI_Flag = 1;
        }

        else if (strcasecmp(str, "OMCtrl_ULMUDataDisable") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            rfeat->OMCtrl_ULMUDataDisable = atoi(str);
        }
        else if (strcasecmp(str, "PPDUTxType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(rfeat->PPDUTxType, str, 8);
            rfeat->PPDUTxType_Flag = 1;
        }
        else if (strcasecmp(str, "MU_EDCA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(rfeat->MU_EDCAType, str);
            rfeat->MU_EDCA_flag = 1;
            printf("\nMUEDCA %s\n flag%d\n", rfeat->MU_EDCAType, rfeat->MU_EDCA_flag);
        }
        else if (strcasecmp(str, "TxSUPPDU") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(rfeat->TxSUPPDUType, str);
            rfeat->TxSUPPDU_flag = 1;
            printf("\nTxSUPPDU %s\n flag%d\n", rfeat->TxSUPPDUType, rfeat->TxSUPPDU_flag);
        }
        else if (strcasecmp(str, "BTWT_ID") == 0)
        {
            str              = strtok_r(NULL, ",", &pcmdStr);
            rfeat->BTWT_ID   = atoi(str);
            rfeat->BTWT_FLAG = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_SET_RFEATURE_TLV, sizeof(caStaRFeat_t), (BYTE *)rfeat, aBuf);
    *aLen = 4 + sizeof(caStaRFeat_t);
    return WFA_SUCCESS;
}

int xcCmdProcStaStartWfdConnection(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaStartWfdConn_t *staStartWfdConn = (caStaStartWfdConn_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    BYTE tmp_cnt;
    char *tmp_str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(pcmdStr, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staStartWfdConn->intf, str, WFA_IF_NAME_LEN - 1);
            staStartWfdConn->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "peeraddress") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            for (tmp_cnt = 0;; tmp_cnt++)
            {
                tmp_str = strtok_r(str, " ", &str);
                if (str == NULL || str[0] == '\0')
                    break;

                strncpy(staStartWfdConn->peer[tmp_cnt], tmp_str, WFA_MAC_ADDR_STR_LEN - 1);
                staStartWfdConn->peer[tmp_cnt][WFA_MAC_ADDR_STR_LEN - 1] = '\0';
            }

            // strncpy(staStartWfdConn->peer, str, WFA_MAC_ADDR_STR_LEN-1);
            // staStartWfdConn->peer[WFA_MAC_ADDR_STR_LEN-1]='\0';
        }
        else if (strcasecmp(str, "init_wfd") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            staStartWfdConn->init_wfd      = atoi(str);
            staStartWfdConn->init_wfd_flag = 1;
        }
        else if (strcasecmp(str, "intent_val") == 0)
        {
            str                              = strtok_r(NULL, ",", &pcmdStr);
            staStartWfdConn->intent_val      = atoi(str);
            staStartWfdConn->intent_val_flag = 1;
        }
        else if (strcasecmp(str, "oper_chn") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            staStartWfdConn->oper_chn      = atoi(str);
            staStartWfdConn->oper_chn_flag = 1;
        }
        else if (strcasecmp(str, "coupledSession") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            staStartWfdConn->coupledSession      = atoi(str);
            staStartWfdConn->coupledSession_flag = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_START_WFD_CONNECTION_TLV, sizeof(caStaStartWfdConn_t), (BYTE *)staStartWfdConn, aBuf);

    *aLen = 4 + sizeof(caStaStartWfdConn_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaCliCommand(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    printf("\n The CA CLI command to DUT is : %s", pcmdStr);
    printf("\n The CA CLI command to DUT Length : %d", strlen(pcmdStr));
    wfaEncodeTLV(WFA_STA_CLI_CMD_TLV, strlen(pcmdStr), (BYTE *)pcmdStr, aBuf);

    *aLen = 4 + strlen(pcmdStr);
    return WFA_SUCCESS;
}

int xcCmdProcStaConnectGoStartWfd(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaConnectGoStartWfd_t *staConnectGoStartWfd = (caStaConnectGoStartWfd_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staConnectGoStartWfd->intf, str, WFA_IF_NAME_LEN - 1);
            staConnectGoStartWfd->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staConnectGoStartWfd->grpid, str, WFA_P2P_GRP_ID_LEN - 1);
            staConnectGoStartWfd->grpid[WFA_P2P_GRP_ID_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "p2pdevid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staConnectGoStartWfd->devId, str, WFA_P2P_DEVID_LEN - 1);
            staConnectGoStartWfd->devId[WFA_P2P_DEVID_LEN - 1] = '\0';
        }
    }

    wfaEncodeTLV(WFA_STA_CONNECT_GO_START_WFD_TLV, sizeof(caStaConnectGoStartWfd_t), (BYTE *)staConnectGoStartWfd,
                 aBuf);

    *aLen = 4 + sizeof(caStaConnectGoStartWfd_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGenerateEvent(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaGenEvent_t *staGenEvent = (caStaGenEvent_t *)(aBuf + sizeof(wfaTLV));
    char *str;
    caWfdStaGenEvent_t *pWfdEvent;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, '\0', *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGenEvent->intf, str, WFA_IF_NAME_LEN - 1);
            staGenEvent->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "WFD") == 0)
            {
                staGenEvent->program = PROG_TYPE_WFD;
                pWfdEvent            = (caWfdStaGenEvent_t *)&staGenEvent->wfdEvent;

                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;

                    if (strcasecmp(str, "type") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "uibc_gen") == 0)
                        {
                            pWfdEvent->type = eUibcGen;
                        }
                        if (strcasecmp(str, "uibc_hid") == 0)
                        {
                            pWfdEvent->type = eUibcHid;
                        }
                        if (strcasecmp(str, "frameskip") == 0)
                        {
                            pWfdEvent->type = eFrameSkip;
                        }
                        if (strcasecmp(str, "inputContent") == 0)
                        {
                            pWfdEvent->type = eInputContent;
                        }
                        if (strcasecmp(str, "i2cread") == 0)
                        {
                            pWfdEvent->type = eI2cRead;
                        }
                        if (strcasecmp(str, "i2cwrite") == 0)
                        {
                            pWfdEvent->type = eI2cWrite;
                        }
                        if (strcasecmp(str, "idrReq") == 0)
                        {
                            pWfdEvent->type = eIdrReq;
                        }
                    }
                    else if (strcasecmp(str, "sessionid") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pWfdEvent->wfdSessionID, str, WFA_WFD_SESSION_ID_LEN - 1);
                        pWfdEvent->wfdSessionID[WFA_WFD_SESSION_ID_LEN - 1] = '\0';
                        pWfdEvent->wfdSessionIdflag                         = 1;
                    }
                    else if (strcasecmp(str, "uibceventtype") == 0)
                    {
                        str                         = strtok_r(NULL, ",", &pcmdStr);
                        pWfdEvent->wfdUibcEventType = eSingleTouchEvent;
                        if (strcasecmp(str, "KeyBoard") == 0)
                        {
                            pWfdEvent->wfdUibcEventType = eKeyBoardEvent;
                        }
                        if (strcasecmp(str, "Mouse") == 0)
                        {
                            pWfdEvent->wfdUibcEventType = eMouseEvent;
                        }
                        pWfdEvent->wfdUibcEventTypeflag = 1;
                    }
                    else if (strcasecmp(str, "uibc_prepare") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "KeyBoard") == 0)
                        {
                            pWfdEvent->wfdUibcEventPrepare = eKeyBoardEvent;
                        }
                        if (strcasecmp(str, "Mouse") == 0)
                        {
                            pWfdEvent->wfdUibcEventPrepare = eMouseEvent;
                        }
                        pWfdEvent->wfdUibcEventPrepareflag = 1;
                    }

                    else if (strcasecmp(str, "frameSkip") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "Start") == 0)
                        {
                            pWfdEvent->wfdFrameSkipRateflag = 1;
                        }
                        else
                        {
                            pWfdEvent->wfdFrameSkipRateflag = 0;
                        }
                    }
                    else if (strcasecmp(str, "InputContentType") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "Protected") == 0)
                        {
                            pWfdEvent->wfdInputContentType = eProtected;
                        }
                        if (strcasecmp(str, "Unprotected") == 0)
                        {
                            pWfdEvent->wfdInputContentType = eUnprotected;
                        }
                        if (strcasecmp(str, "ProtectedVideoOnly") == 0)
                        {
                            pWfdEvent->wfdInputContentType = eProtectedVideoOnly;
                        }
                        pWfdEvent->wfdInputContentTypeflag = 1;
                    }
                    else if (strcasecmp(str, "I2c_Struct") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(pWfdEvent->wfdI2cData, str, strlen(str));
                        pWfdEvent->wfdI2cData[31] = '\0';
                        pWfdEvent->wfdI2cDataflag = 1;
                    }
                }
            }
        }
    }

    wfaEncodeTLV(WFA_STA_GENERATE_EVENT_TLV, sizeof(caStaGenEvent_t), (BYTE *)staGenEvent, aBuf);

    *aLen = 4 + sizeof(caStaGenEvent_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaReinvokeWfdSession(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaReinvokeWfdSession_t *staReinvokeWfdSession = (caStaReinvokeWfdSession_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staReinvokeWfdSession->intf, str, WFA_IF_NAME_LEN - 1);
            staReinvokeWfdSession->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "groupid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staReinvokeWfdSession->grpid, str, WFA_P2P_GRP_ID_LEN - 1);
            staReinvokeWfdSession->grpid[WFA_P2P_GRP_ID_LEN - 1] = '\0';
            staReinvokeWfdSession->grpid_flag                    = 1;
        }
        else if (strcasecmp(str, "PeerAddress") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staReinvokeWfdSession->peer, str, WFA_MAC_ADDR_STR_LEN - 1);
            staReinvokeWfdSession->peer[WFA_MAC_ADDR_STR_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "invitationaction") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Send") == 0)
            {
                staReinvokeWfdSession->wfdInvitationAction = eInvitationSend;
            }
            else if (strcasecmp(str, "Accept") == 0)
            {
                staReinvokeWfdSession->wfdInvitationAction = eInvitationAccept;
            }
        }
    }

    wfaEncodeTLV(WFA_STA_REINVOKE_WFD_SESSION_TLV, sizeof(caStaReinvokeWfdSession_t), (BYTE *)staReinvokeWfdSession,
                 aBuf);

    *aLen = 4 + sizeof(caStaReinvokeWfdSession_t);

    return WFA_SUCCESS;
}

int xcCmdProcStaGetParameter(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caStaGetParameter_t *staGetParameter = (caStaGetParameter_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(staGetParameter->intf, str, WFA_IF_NAME_LEN - 1);
            staGetParameter->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        if (strcasecmp(str, "PMK") == 0)
        {
            staGetParameter->rssi_flag       = 0;
            staGetParameter->pmk_flag        = 1;
            staGetParameter->getParamValue   = ePMK;
            staGetParameter->getParamValFlag = 3;
            DPRINT_INFO(WFA_OUT, "PMK FLAG set... Return PMKID \n");
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            {
                if (strcasecmp(str, "WFD") == 0)
                {
                    staGetParameter->program = PROG_TYPE_WFD;
                    str                      = strtok_r(NULL, ",", &pcmdStr);
                    if (strcasecmp(str, "Parameter") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "DiscoveredDevList") == 0)
                        {
                            staGetParameter->getParamValue   = eDiscoveredDevList;
                            staGetParameter->getParamValFlag = 1;
                        }
                    }
                }
                else if (strcasecmp(str, "HE") == 0)
                {
                    staGetParameter->program = PROG_TYPE_HE;
                    str                      = strtok_r(NULL, ",", &pcmdStr);
                    if (strcasecmp(str, "Parameter") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strcasecmp(str, "rssi") == 0)
                        {
                            staGetParameter->pmk_flag        = 0;
                            staGetParameter->rssi_flag       = 1;
                            staGetParameter->getParamValue   = eRSSI;
                            staGetParameter->getParamValFlag = 2;
                            DPRINT_INFO(WFA_OUT, "RSSI FLAG set... Calculate RSSI\n");
                        }
                        if (strcasecmp(str, "PMK") == 0)
                        {
                            staGetParameter->rssi_flag       = 0;
                            staGetParameter->pmk_flag        = 1;
                            staGetParameter->getParamValFlag = 3;
                            DPRINT_INFO(WFA_OUT, "PMK FLAG set... Return PMKID \n");
                        }
                    }
                }
            }
        }
    }
    wfaEncodeTLV(WFA_STA_GET_PARAMETER_TLV, sizeof(caStaGetParameter_t), (BYTE *)staGetParameter, aBuf);

    *aLen = 4 + sizeof(caStaGetParameter_t);

    return WFA_SUCCESS;
}

#ifdef EXPERIMENTAL_AP_SUPPORT
int xcCmdProcAPReboot(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPReboot_t *apReboot;
    apReboot = (caAPReboot_t *)(aBuf + sizeof(wfaTLV));

    wfaEncodeTLV(WFA_AP_REBOOT_TLV, sizeof(caAPReboot_t), (BYTE *)apReboot, aBuf);

    *aLen = 4 + sizeof(caAPReboot_t);

    return WFA_SUCCESS;
}
int xcCmdProcAPConfigCommit(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetSecurity_t *apSecurity;
    apSecurity = (caAPSetSecurity_t *)(aBuf + sizeof(wfaTLV));

    wfaEncodeTLV(WFA_AP_CONFIG_COMMIT_TLV, sizeof(caAPSetSecurity_t),

                 (BYTE *)apSecurity, aBuf);
    *aLen = 4 + sizeof(caAPSetSecurity_t);

    printf("process cmd2\n");
    return TRUE;
}
int xcCmdProcAPSetSecurity(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetSecurity_t *apSecurity;
    apSecurity = (caAPSetSecurity_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    printf("process cmd\n");
    if (aBuf == NULL)
        return FALSE;

    printf("process cmd1\n");
    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        printf("=> %s", str);
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurity->intf, str, WFA_IF_NAME_LEN - 1);
            apSecurity->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurity->name, str, WFA_AP_NAME_LEN);
            apSecurity->name[WFA_AP_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "keymgnt") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apSecurity->keymgnt, str, WFA_AP_KEYMGMT_LEN);
            apSecurity->name[WFA_AP_KEYMGMT_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "encrypt") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->encry_flag = 1;
            strncpy(apSecurity->encrypt, str, WFA_AP_ENCRY_LEN);
            apSecurity->name[WFA_AP_ENCRY_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "psk") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->psk_flag = 1;
            strncpy(apSecurity->psk, str, WFA_AP_PASSPHRASE_LEN);
            apSecurity->psk[WFA_AP_PASSPHRASE_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "wepkey") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->wep_flag = 1;
            strncpy(apSecurity->wepkey, str, WFA_AP_WEPKEY_LEN);
            apSecurity->wepkey[WFA_AP_WEPKEY_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "pmf") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->pmf_flag = 1;
            strncpy(apSecurity->pmf, str, 16);
            printf("\nThe pmf is set to %s\n", apSecurity->pmf);
        }
        else if (strcasecmp(str, "sha256ad") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->sha_flag = 1;
            strncpy(apSecurity->sha256ad, str, 16);
        }
        // printf(": %s\n", str);
        else if (strcasecmp(str, "sae_pwe") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apSecurity->sae_pwe, str);
            if (!strcasecmp(apSecurity->sae_pwe, "h2e"))
            {
                apSecurity->sae_pwe_flag = 1;
                printf("\n SAE-H2E only\n");
            }
            else
            {
                apSecurity->sae_pwe_flag = 0;
                printf("\n SAE-H2E+HP\n");
            }
        }
        else if (strcasecmp(str, "ECGroupID") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->ECGroupID_flag = 1;
            strcpy(apSecurity->ECGroup_ID, str);
        }
        else if (strcasecmp(str, "AKMSuiteType") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->AKMSuiteType_flag = 1;
            strcpy(apSecurity->AKMSuiteType, str);
            printf("\nthe AKM suite is %s\n", apSecurity->AKMSuiteType);
            if (!strcasecmp(apSecurity->AKMSuiteType, "2;8"))
                printf("\n This is WPA2-PSK-SAE");
            if (!strcasecmp(apSecurity->AKMSuiteType, "8"))
                printf("\nThis is SAE with SHA-256\n");
        }
        else if (strcasecmp(str, "SAEPasswords") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->SAEPasswords_flag = 1;
            strncpy(apSecurity->SAEPasswords, str, WFA_AP_PASSPHRASE_LEN);
            apSecurity->SAEPasswords[WFA_AP_PASSPHRASE_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "Transition_Disable") == 0)
        {
            str                                 = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->Transition_Disable_flag = 1;
            apSecurity->Transition_Disable      = atoi(str);
        }
        else if (strcasecmp(str, "Transition_Disable_Index") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            apSecurity->Transition_Disable_Index = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_SECURITY_TLV, sizeof(caAPSetSecurity_t),

                 (BYTE *)apSecurity, aBuf);
    *aLen = 4 + sizeof(caAPSetSecurity_t);

    printf("process cmd2\n");
    return TRUE;
}
/* SSID
 * CHANNEL
 * MODE
 * WME
 * WMMPS
 * RTS - int
 * FRGMNT - int
 * PWRSAVE
 * BCNINT
 * RADIO       -bool
 * P2PMgmtBit       -bool
 * ChannelUsage
 * TDLSProhibit          bool
 * TDLSChswitchProhibit      bool*/

int xcCmdProcAPSetWireless(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetWireless_t *apWireless;
    apWireless = (caAPSetWireless_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    printf("process cmd\n");
    if (aBuf == NULL)
        return FALSE;

    printf("process cmd1\n");
    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        printf("=> %s", str);
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->intf, str, WFA_IF_NAME_LEN - 1);
            apWireless->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->name, str, WFA_AP_NAME_LEN);
            apWireless->name[WFA_AP_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "ssid") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->ssid, str, WFA_AP_SSID_LEN);
            apWireless->ssid[WFA_AP_SSID_LEN - 1] = '\0';
            apWireless->ssid_flag                 = 1;
            /*if (strstr(apWireless->ssid,"HE") != NULL)  {
                if (strstr(apWireless->ssid,"24G") != NULL)
                { BAND_24G = 1;
                 BAND_5G = 0;
                }
                else
                    { BAND_24G = 0;
                 BAND_5G = 1;
                }
             }*/
        }
        else if (strcasecmp(str, "width") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->width      = atoi(str);
            apWireless->width_flag = 1;
        }
        else if (strcasecmp(str, "channel") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            apWireless->channel      = atoi(str);
            apWireless->channel_flag = 1;
            if ((51 < apWireless->channel) && (apWireless->channel < 141))
                apWireless->DFS_CHAN_FLAG = 1;
            if ((apWireless->width != 20) &&
                ((1 == apWireless->channel) || (2 == apWireless->channel) || (3 == apWireless->channel) ||
                 (4 == apWireless->channel) || (5 == apWireless->channel) || (6 == apWireless->channel) ||
                 (7 == apWireless->channel) || (8 == apWireless->channel) || (9 == apWireless->channel) ||
                 (10 == apWireless->channel) || (36 == apWireless->channel) || (44 == apWireless->channel) ||
                 (52 == apWireless->channel) || (60 == apWireless->channel) || (100 == apWireless->channel) ||
                 (108 == apWireless->channel) || (116 == apWireless->channel) || (124 == apWireless->channel) ||
                 (132 == apWireless->channel) || (149 == apWireless->channel) || (157 == apWireless->channel)))
            {
                apWireless->HT_40_PLUS_FLAG  = 1;
                apWireless->HT_40_MINUS_FLAG = 0;
            }
            if ((apWireless->width != 20) &&
                ((11 == apWireless->channel) || (40 == apWireless->channel) || (48 == apWireless->channel) ||
                 (56 == apWireless->channel) || (64 == apWireless->channel) || (104 == apWireless->channel) ||
                 (112 == apWireless->channel) || (120 == apWireless->channel) || (128 == apWireless->channel) ||
                 (136 == apWireless->channel) || (144 == apWireless->channel) || (153 == apWireless->channel) ||
                 (161 == apWireless->channel)))
            {
                apWireless->HT_40_PLUS_FLAG  = 0;
                apWireless->HT_40_MINUS_FLAG = 1;
            }
            if ((140 == apWireless->channel) || (165 == apWireless->channel))
                apWireless->HT_20_ONLY_FLAG = 1;
            {
                if (35 < apWireless->channel)
                {
                    BAND_24G = 0;
                    BAND_5G  = 1;
                }
                else
                {
                    BAND_24G = 1;
                    BAND_5G  = 0;
                }
            }
        }
        else if (strcasecmp(str, "chnlfreq") == 0)
        {
            str                       = strtok_r(NULL, ",", &pcmdStr);
            apWireless->chnlfreq      = atoi(str);
            apWireless->chnlfreq_flag = 1;
        }
        else if (strcasecmp(str, "mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->mode, str, 10);
            apWireless->mode_flag = 1;
        }
        else if (strcasecmp(str, "wme") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->wme, str, 10);
            apWireless->wme_flag = 1;
        }
        else if (strcasecmp(str, "wmmps") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->wmmps, str, 10);
            apWireless->wmmps_flag = 1;
        }
        else if (strcasecmp(str, "rts") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apWireless->rts      = atoi(str);
            apWireless->rts_flag = 1;
        }
        else if (strcasecmp(str, "frgmnt") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            apWireless->frgmnt      = atoi(str);
            apWireless->frgmnt_flag = 1;
        }
        else if (strcasecmp(str, "pwrsave") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->powersave, str, 10);
            apWireless->ps_flag = 1;
        }
        else if (strcasecmp(str, "bcnint") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->bcnint, str, 10);
            apWireless->bcnint_flag = 1;
        }
        else if (strcasecmp(str, "radio") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "on") == 0)
                apWireless->radio = WFA_ENABLED;
            else
                apWireless->radio = WFA_DISABLED;
            apWireless->radio_flag = 1;
        }
        else if (strcasecmp(str, "P2PMgmtBit") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apWireless->p2p_mgmt_bit      = atoi(str);
            apWireless->p2p_mgmt_bit_flag = 1;
        }
        else if (strcasecmp(str, "channelusage") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->channel_usage, str, 10);
            apWireless->channel_usage_flag = 1;
        }
        else if (strcasecmp(str, "tdlsprohibit") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "Enabled") == 0)
                apWireless->tdls_prohibit = WFA_ENABLED;
            else
                apWireless->tdls_prohibit = WFA_DISABLED;
            apWireless->tdls_prohibit_flag = 1;
        }
        else if (strcasecmp(str, "TDLSChswitchProhibit") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);

            if (strcasecmp(str, "Enabled") == 0)
                apWireless->tdls_ch_switch_prohibit = WFA_ENABLED;
            else
                apWireless->tdls_ch_switch_prohibit = WFA_DISABLED;
            apWireless->tdls_ch_switch_prohibit_flag = 1;
        }
        else if (strcasecmp(str, "addba_reject") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apWireless->addba_reject      = wfaStandardBoolParsing(str);
            apWireless->addba_reject_flag = 1;
        }
        else if (strcasecmp(str, "mcs_fixedrate") == 0)
        {
            str                            = strtok_r(NULL, ",", &pcmdStr);
            apWireless->mcs_fixedrate      = atoi(str);
            apWireless->mcs_fixedrate_flag = 1;
        }
        else if (strcasecmp(str, "spatial_tx_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "1ss") == 0 || strcasecmp(str, "1") == 0)
                apWireless->spatial_tx_stream = 1;
            else if (strcasecmp(str, "2ss") == 0 || strcasecmp(str, "2") == 0)
                apWireless->spatial_tx_stream = 2;
            else if (strcasecmp(str, "3ss") == 0 || strcasecmp(str, "3") == 0)
                apWireless->spatial_tx_stream = 3;
            else
                apWireless->spatial_tx_stream = 2; /*default*/
            apWireless->spatial_tx_stream_flag = 1;
        }
        else if (strcasecmp(str, "ampdu") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->ampdu      = wfaStandardBoolParsing(str);
            apWireless->ampdu_flag = 1;
        }
        else if (strcasecmp(str, "amsdu") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->amsdu      = wfaStandardBoolParsing(str);
            apWireless->amsdu_flag = 1;
        }
        else if (strcasecmp(str, "spatial_rx_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "1ss") == 0 || strcasecmp(str, "1") == 0)
                apWireless->spatial_rx_stream = 1;
            else if (strcasecmp(str, "2ss") == 0 || strcasecmp(str, "2") == 0)
                apWireless->spatial_rx_stream = 2;
            else if (strcasecmp(str, "3ss") == 0 || strcasecmp(str, "3") == 0)
                apWireless->spatial_rx_stream = 3;
            else
                apWireless->spatial_rx_stream = 2; /*default*/
            apWireless->spatial_rx_stream_flag = 1;
        }
        else if (strcasecmp(str, "vht_tkip") == 0)
        {
            str                       = strtok_r(NULL, ",", &pcmdStr);
            apWireless->vht_tkip      = wfaStandardBoolParsing(str);
            apWireless->vht_tkip_flag = 1;
        }
        else if (strcasecmp(str, "vht_wep") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            apWireless->vht_wep      = wfaStandardBoolParsing(str);
            apWireless->vht_wep_flag = 1;
        }
        else if (strcasecmp(str, "stbc_tx") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            apWireless->stbc_tx      = atoi(str);
            apWireless->stbc_tx_flag = 1;
        }
        else if (strcasecmp(str, "txbf") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->tx_bf      = wfaStandardBoolParsing(str);
            apWireless->tx_bf_flag = 1;
        }
        else if (strcasecmp(str, "HTC-VHT") == 0)
        {
            str                      = strtok_r(NULL, ",", &pcmdStr);
            apWireless->htc_vht      = !strcasecmp(str, "enable");
            apWireless->htc_vht_flag = 1;
        }
        else if (strcasecmp(str, "nss_mcs_cap") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(apWireless->nssMCSCap, str, 7);
            apWireless->nssMCSCap_flag = 1;
            printf("\nsta got nss_mcs_cap para:%s\n\n", apWireless->nssMCSCap);
        }
        else if (strcasecmp(str, "BW_SGNL") == 0)
        {
            str                        = strtok_r(NULL, ",", &pcmdStr);
            apWireless->bw_signal      = wfaStandardBoolParsing(str);
            apWireless->bw_signal_flag = 1;
        }
        else if (strcasecmp(str, "DYN_BW_SGNL") == 0)
        {
            printf("\n===> Rcvd dyn bw signal\n");
            str                            = strtok_r(NULL, ",", &pcmdStr);
            apWireless->dyn_bw_signal      = !strcasecmp(str, "enable");
            apWireless->dyn_bw_signal_flag = 1;
        }
        else if (strcasecmp(str, "LDPC") == 0)
        {
            str                   = strtok_r(NULL, ",", &pcmdStr);
            apWireless->ldpc      = !strcasecmp(str, "enable");
            apWireless->ldpc_flag = 1;
        }
        else if (strcasecmp(str, "SpectrumMgt") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apWireless->spectrum_mgt      = !strcasecmp(str, "enable");
            apWireless->spectrum_mgt_flag = 1;
        }
        else if (strcasecmp(str, "CountryCode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            memset(apWireless->country_code, 0, 4);
            strncpy(apWireless->country_code, str, 2);
            apWireless->country_code_flag = 1;
            printf("\n\n\t The country code flag is SET to %d\n\n\r", apWireless->country_code_flag);
        }
        else if (strcasecmp(str, "Protect_mode") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apWireless->protect_mode      = !strcasecmp(str, "enable");
            apWireless->protect_mode_flag = 1;
        }
        else if (strcasecmp(str, "sgi80") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->sgi80      = wfaStandardBoolParsing(str);
            apWireless->sgi80_flag = 1;
        }
        else if (strcasecmp(str, "greenfield") == 0)
        {
            str                 = strtok_r(NULL, ",", &pcmdStr);
            apWireless->gf      = !strcasecmp(str, "enable");
            apWireless->gf_flag = 1;
        }
        else if (strcasecmp(str, "sgi20") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->sgi20      = !strcasecmp(str, "enable");
            apWireless->sgi20_flag = 1;
        }
        else if (strcasecmp(str, "mcs_32") == 0)
        {
            str                    = strtok_r(NULL, ",", &pcmdStr);
            apWireless->mcs32      = !strcasecmp(str, "enable");
            apWireless->mcs32_flag = 1;
        }
        else if (strcasecmp(str, "Cellular_Cap_Pref") == 0)
        {
            str                                = strtok_r(NULL, ",", &pcmdStr);
            apWireless->Cellular_Cap_Pref      = atoi(str);
            apWireless->Cellular_Cap_Pref_flag = 1;
        }
        else if (strcasecmp(str, "GAS_CB_Delay") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            apWireless->GAS_CB_Delay      = atoi(str);
            apWireless->GAS_CB_Delay_flag = 1;
        }
        else if (strcasecmp(str, "Reg_Domain") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apWireless->Reg_Domain, str);
            apWireless->Reg_Domain_flag = 1;
        }
        // DD-HE-AP
        else if (strcasecmp(str, "PPDUTxType") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apWireless->PPDUTxType, str);
            apWireless->PPDUTxType_flag = 1;
        }
        else if (strcasecmp(str, "OFDMA") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apWireless->OFDMA, str);
            apWireless->OFDMA_flag = 1;
        }
        else if (strcasecmp(str, "BA_Recv_Status") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apWireless->BA_Recv_Status, str);
            apWireless->BA_Recv_Status_flag = 1;
        }
        else if (strcasecmp(str, "MIMO") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(apWireless->MIMO, str);
            apWireless->MIMO_flag = 1;
        }
        else if (strcasecmp(str, "BCC") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            apWireless->BCC      = !strcasecmp(str, "enable");
            apWireless->BCC_flag = 1;
        }
        else if (strcasecmp(str, "HE_TXOPDurRTSThr") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            apWireless->HE_TXOPDurRTSThr      = !strcasecmp(str, "enable");
            apWireless->HE_TXOPDurRTSThr_flag = 1;
        }
        else if (strcasecmp(str, "ADDBAResp_BufSize") == 0)
        {
            str                                = strtok_r(NULL, ",", &pcmdStr);
            apWireless->ADDBAResp_BufSize      = atoi(str);
            apWireless->ADDBAResp_BufSize_flag = 1;
        }
        else if (strcasecmp(str, "ADDBAReq_BufSize") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            apWireless->ADDBAReq_BufSize      = atoi(str);
            apWireless->ADDBAReq_BufSize_flag = 1;
        }
        else if (strcasecmp(str, "Band6Gonly") == 0)
        {
            str                         = strtok_r(NULL, ",", &pcmdStr);
            apWireless->band6gonly      = !strcasecmp(str, "enable");
            apWireless->band6gonly_flag = 1;
        }
        printf(": %s\n", str);
    }

    wfaEncodeTLV(WFA_AP_SET_WIRELESS_TLV, sizeof(caAPSetWireless_t), (BYTE *)apWireless, aBuf);
    *aLen = 4 + sizeof(caAPSetWireless_t);

    printf("process cmd2\n");
    return TRUE;
}

int xcCmdProcAPSet11n(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSet11n_t *ap11n;
    ap11n = (caAPSet11n_t *)(aBuf + sizeof(wfaTLV));

    /* @TODO: Process ap_set_11n command params
     * Most of the command parameters are similar to ap_set_wireless.
     * So, this commadn is deprecated and UCC must send ap_set_wireless instead.
     * */

    printf(
        "==> Deprecated command ap_set_11n received from UCC\nPlease consider"
        "upgrading the command call to ap_set_wireless\n\n");

    wfaEncodeTLV(WFA_AP_SET_11N_TLV, sizeof(caAPSet11n_t), (BYTE *)ap11n, aBuf);
    *aLen = 4 + sizeof(caAPSet11n_t);

    return TRUE;
}

// DD 11N 80211h API implementation
int xcCmdProcAPSet11h(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSet11h_t *ap11h;
    ap11h = (caAPSet11h_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "regulatory_mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap11h->regulatory_mode, str, 4);
        }
        else if (strcasecmp(str, "sim_dfs") == 0)
        {
            ap11h->sim_dfs_flag = 1;
            printf("\n\n\r EXECUTE THE COMMAND FOR CHANNEL SWITCH");
        }
        else if (strcasecmp(str, "dfs_mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap11h->dfs_mode, str, 8);
            if (!(strcasecmp(ap11h->dfs_mode, "enable")))
                ap11h->dfs_flag = 1;
        }
        else if (strcasecmp(str, "dfs_chan") == 0)
        {
            str             = strtok_r(NULL, ",", &pcmdStr);
            ap11h->dfs_chan = atoi(str);
            ap11h->dfs_flag = 1;
        }
    }

    wfaEncodeTLV(WFA_AP_SET_11H_TLV, sizeof(caAPSet11h_t), (BYTE *)ap11h, aBuf);
    *aLen = 4 + sizeof(caAPSet11h_t);

    return TRUE;
}
// DD: 80211H for 11N API Implementation Completed

// AK: AP dev_exec_action API implementation
int xcCmdProcDevExecAction(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caDevExecAction_t *execAction = (caDevExecAction_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(execAction->intf, str, 15);
        }
        else if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(execAction->name, str, 16);
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(execAction->prog, str, 8);
        }
        else if (strcasecmp(str, "KeyRotation") == 0)
        {
            str                     = strtok_r(NULL, ",", &pcmdStr);
            execAction->keyrotation = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_DEV_EXEC_ACTION_TLV, sizeof(caDevExecAction_t), (BYTE *)execAction, aBuf);
    *aLen = 4 + sizeof(caDevExecAction_t);

    return TRUE;
}

int xcCmdProcAPSet11d(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSet11d_t *ap11d;
    ap11d = (caAPSet11d_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "regulatory_mode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap11d->regulatory_mode, str, 4);
        }
        else if (strcasecmp(str, "CountryCode") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap11d->CountryCode, str, 4);
            printf("\n\n\rAP_SET_11D API called for country code");
            ap11d->CountryCode_flag = 1;
            printf("\n\n\rCountry Code Flag Set to %d", ap11d->CountryCode_flag);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_11D_TLV, sizeof(caAPSet11d_t), (BYTE *)ap11d, aBuf);
    *aLen = 4 + sizeof(caAPSet11d_t);

    return TRUE;
}

int xcCmdProcAPResetDefault(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPResetDefault_t *reset;
    reset = (caAPResetDefault_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(reset->intf, str, 15);
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(reset->prog, str, 8);
        }
        else if (strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            memset(reset->type, 0, sizeof(reset->type));
            strncpy(reset->type, str, sizeof(reset->type));
            if (!strcasecmp(reset->type, "Testbed"))
            {
                reset->testbed = 1;
                printf("Device type is testbed\n\n");
            }
        }
    }

    wfaEncodeTLV(WFA_AP_RESET_DEFAULT_TLV, sizeof(caAPResetDefault_t), (BYTE *)reset, aBuf);
    *aLen = 4 + sizeof(caAPResetDefault_t);

    return TRUE;
}

int xcCmdProcAPSetStaQos(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetStaQos_t *ap_set_sta_qos;
    ap_set_sta_qos = (caAPSetStaQos_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    printf("process cmd\n");
    if (aBuf == NULL)
        return FALSE;

    printf("process cmd1\n");
    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        printf("=> %s\n", str);
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_sta_qos->intf, str, WFA_IF_NAME_LEN - 1);
            ap_set_sta_qos->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "cwmin_vo") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vo.cwmin      = atoi(str);
            ap_set_sta_qos->vo.cwmin_flag = 1;
            ap_set_sta_qos->vo_flag       = 1;
        }
        else if (strcasecmp(str, "cwmax_vo") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vo.cwmax      = atoi(str);
            ap_set_sta_qos->vo.cwmax_flag = 1;
            ap_set_sta_qos->vo_flag       = 1;
        }
        else if (strcasecmp(str, "aifs_vo") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vo.aifs      = atoi(str);
            ap_set_sta_qos->vo.aifs_flag = 1;
            ap_set_sta_qos->vo_flag      = 1;
        }
        else if (strcasecmp(str, "txop_vo") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vo.txop      = atoi(str);
            ap_set_sta_qos->vo.txop_flag = 1;
            ap_set_sta_qos->vo_flag      = 1;
        }
        else if (strcasecmp(str, "cwmin_vi") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vi.cwmin      = atoi(str);
            ap_set_sta_qos->vi.cwmin_flag = 1;
            ap_set_sta_qos->vi_flag       = 1;
        }
        else if (strcasecmp(str, "cwmax_vi") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vi.cwmax      = atoi(str);
            ap_set_sta_qos->vi.cwmax_flag = 1;
            ap_set_sta_qos->vi_flag       = 1;
        }
        else if (strcasecmp(str, "aifs_vi") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vi.aifs      = atoi(str);
            ap_set_sta_qos->vi.aifs_flag = 1;
            ap_set_sta_qos->vi_flag      = 1;
        }
        else if (strcasecmp(str, "txop_vi") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->vi.txop      = atoi(str);
            ap_set_sta_qos->vi.txop_flag = 1;
            ap_set_sta_qos->vi_flag      = 1;
        }
        else if (strcasecmp(str, "cwmin_bk") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->bk.cwmin      = atoi(str);
            ap_set_sta_qos->bk.cwmin_flag = 1;
            ap_set_sta_qos->bk_flag       = 1;
        }
        else if (strcasecmp(str, "cwmax_bk") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->bk.cwmax      = atoi(str);
            ap_set_sta_qos->bk.cwmax_flag = 1;
            ap_set_sta_qos->bk_flag       = 1;
        }
        else if (strcasecmp(str, "aifs_bk") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->bk.aifs      = atoi(str);
            ap_set_sta_qos->bk.aifs_flag = 1;
            ap_set_sta_qos->bk_flag      = 1;
        }
        else if (strcasecmp(str, "txop_bk") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->bk.txop      = atoi(str);
            ap_set_sta_qos->bk.txop_flag = 1;
            ap_set_sta_qos->bk_flag      = 1;
        }
        else if (strcasecmp(str, "cwmin_be") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->be.cwmin      = atoi(str);
            ap_set_sta_qos->be.cwmin_flag = 1;
            ap_set_sta_qos->be_flag       = 1;
        }
        else if (strcasecmp(str, "cwmax_be") == 0)
        {
            str                           = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->be.cwmax      = atoi(str);
            ap_set_sta_qos->be.cwmax_flag = 1;
            ap_set_sta_qos->be_flag       = 1;
        }
        else if (strcasecmp(str, "aifs_be") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->be.aifs      = atoi(str);
            ap_set_sta_qos->be.aifs_flag = 1;
            ap_set_sta_qos->be_flag      = 1;
        }
        else if (strcasecmp(str, "txop_be") == 0)
        {
            str                          = strtok_r(NULL, ",", &pcmdStr);
            ap_set_sta_qos->be.txop      = atoi(str);
            ap_set_sta_qos->be.txop_flag = 1;
            ap_set_sta_qos->be_flag      = 1;
        }
    }
    wfaEncodeTLV(WFA_AP_SET_STA_QOS_TLV, sizeof(caAPSetStaQos_t), (BYTE *)ap_set_sta_qos, aBuf);
    *aLen = 4 + sizeof(caAPSetStaQos_t);

    return TRUE;
}

int xcCmdProcAPSetAPQos(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetAPQos_t *ap_set_ap_qos;
    ap_set_ap_qos = (caAPSetAPQos_t *)(aBuf + sizeof(wfaTLV));

    wfaEncodeTLV(WFA_AP_SET_AP_QOS_TLV, sizeof(caAPSetAPQos_t), (BYTE *)ap_set_ap_qos, aBuf);
    *aLen = 4 + sizeof(caAPSetAPQos_t);

    return TRUE;
}

int xcCmdProcAPSendADDBAReq(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSendADDBAReq_t *ap_send_addba_req;
    ap_send_addba_req = (caAPSendADDBAReq_t *)(aBuf + sizeof(wfaTLV));

    wfaEncodeTLV(WFA_AP_SEND_ADDBA_REQ_TLV, sizeof(caAPSendADDBAReq_t), (BYTE *)ap_send_addba_req, aBuf);
    *aLen = 4 + sizeof(caAPSendADDBAReq_t);

    return TRUE;
}

int xcCmdProcAPSetRfeature(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetRfeature_t *ap_set_rfeature;
    ap_set_rfeature = (caAPSetRfeature_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    printf("process cmd\n");
    if (aBuf == NULL)
        return FALSE;

    printf("process cmd1\n");
    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        printf("=> %s\n", str);
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->intf, str, WFA_IF_NAME_LEN - 1);
            ap_set_rfeature->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "name") == 0)
        {
        }
        else if (strcasecmp(str, "nss_mcs_opt") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ap_set_rfeature->nss_mcs_opt, str);
            ap_set_rfeature->nss_mcs_opt_flag = 1;
        }
        else if (strcasecmp(str, "opt_md_notif_ie") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->optMNotifIE, str, 7);
            ap_set_rfeature->optMNotifIE_flag = 1;
        }
        else if (strcasecmp(str, "chnum_band") == 0)
        {
            str = strtok_r(NULL, ";", &pcmdStr);
            printf("AP switching: chan:%s\n", str);
            ap_set_rfeature->csa_chnum = atoi(str);
            printf("AP switching: csa_chnum=%d\n", ap_set_rfeature->csa_chnum);
            str = strtok_r(NULL, "", &pcmdStr);
            printf("AP switching: bandwidth:%s\n", str);
            ap_set_rfeature->csa_width           = atoi(str);
            ap_set_rfeature->csa_chnum_band_flag = 1;
        }
        else if (strcasecmp(str, "BTMReq_DisAssoc_Imnt") == 0)
        {
            str                                        = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->BTMReq_DisAssoc_Imnt      = atoi(str);
            ap_set_rfeature->BTMReq_DisAssoc_Imnt_flag = 1;
        }
        else if (strcasecmp(str, "BTMReq_Term_Bit") == 0)
        {
            str                                   = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->BTMReq_Term_Bit      = atoi(str);
            ap_set_rfeature->BTMReq_Term_Bit_flag = 1;
        }
        else if (strcasecmp(str, "Assoc_Disallow") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(ap_set_rfeature->Assoc_Disallow, str);
            ap_set_rfeature->Assoc_Disallow_flag = 1;
        }
        else if (strcasecmp(str, "Nebor_BSSID") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Nebor_BSSID      = atoi(str);
            ap_set_rfeature->Nebor_BSSID_flag = 1;
        }
        else if (strcasecmp(str, "Nebor_Op_Class") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Nebor_Op_Class      = atoi(str);
            ap_set_rfeature->Nebor_Op_Class_flag = 1;
        }
        else if (strcasecmp(str, "Nebor_Op_Ch") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Nebor_Op_Ch      = atoi(str);
            ap_set_rfeature->Nebor_Op_Ch_flag = 1;
        }
        else if (strcasecmp(str, "Disassoc_Timer") == 0)
        {
            str                                  = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Disassoc_Timer      = atoi(str);
            ap_set_rfeature->Disassoc_Timer_flag = 1;
        }
        else if (strcasecmp(str, "Assoc_Delay") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Assoc_Delay      = atoi(str);
            ap_set_rfeature->Assoc_Delay_flag = 1;
        }
        else if (strcasecmp(str, "Nebor_Pref") == 0)
        {
            str                              = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->Nebor_Pref      = atoi(str);
            ap_set_rfeature->Nebor_Pref_flag = 1;
        }
        else if (strcasecmp(str, "BSS_Term_Duration") == 0)
        {
            str                                     = strtok_r(NULL, ",", &pcmdStr);
            ap_set_rfeature->BSS_Term_Duration      = atoi(str);
            ap_set_rfeature->BSS_Term_Duration_flag = 1;
        }
        else if (strcasecmp(str, "LTF") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->LTF, str, 4);
            ap_set_rfeature->LTF_Flag = 1;
        }
        else if (strcasecmp(str, "GI") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->GI, str, 4);
            ap_set_rfeature->GI_Flag = 1;
        }
        else if (strcasecmp(str, "txBandwidth") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->txBandwidth, str, 4);
            ap_set_rfeature->txBandwidth_flag = 1;
        }
        else if (strcasecmp(str, "HE_TXOPDurRTSThr") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_rfeature->HE_TXOPDurRTSThr, str, 4);
            ap_set_rfeature->HE_TXOPDurRTSThr_flag = 1;
        }
        else if (BAND_24G == 1)
        {
            ap_set_rfeature->HE_BAND_24G = 1;
            ap_set_rfeature->HE_BAND_5G  = 0;
            printf("The value of rfeature band is  %d \n\r", ap_set_rfeature->HE_BAND_24G);
        }
        else if (BAND_5G == 1)
        {
            ap_set_rfeature->HE_BAND_5G  = 1;
            ap_set_rfeature->HE_BAND_24G = 0;
            printf("The value of rfeature band is  %d \n\r", ap_set_rfeature->HE_BAND_5G);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_RFEATURE_TLV, sizeof(caAPSetRfeature_t), (BYTE *)ap_set_rfeature, aBuf);
    *aLen = 4 + sizeof(caAPSetRfeature_t);

    return TRUE;
}

int xcCmdProcAPSetRaduis(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caAPSetRadius_t *ap_set_radius;
    ap_set_radius = (caAPSetRadius_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    printf("process cmd:%s\n", pcmdStr);
    if (aBuf == NULL)
    {
        printf("aBuf is NULL!\n");
        return FALSE;
    }

    memset(aBuf, 0, *aLen);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;
        printf("%s()=> %s:", __func__, str);
        if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_radius->name, str, WFA_AP_NAME_LEN);
            ap_set_radius->name[WFA_AP_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_radius->intf, str, WFA_IF_NAME_LEN - 1);
            ap_set_radius->intf[WFA_IF_NAME_LEN - 1] = '\0';
        }
        else if (strcasecmp(str, "ipaddr") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_radius->as_ip, str, 32);
            ap_set_radius->as_ip[31]  = '\0';
            ap_set_radius->as_ip_flag = 1;
        }
        else if (strcasecmp(str, "port") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_radius->as_port, str, 8);
            ap_set_radius->as_port[7]   = '\0';
            ap_set_radius->as_port_flag = 1;
        }
        else if (strcasecmp(str, "PASSWORD") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ap_set_radius->as_passwd, str, 128);
            ap_set_radius->as_passwd[127] = '\0';
            ap_set_radius->as_passwd_flag = 1;
        }
        else
        {
            printf("Unknow str:%s\n", str);
            continue;
        }
        printf("%s\n", str);
    }

    wfaEncodeTLV(WFA_AP_SET_RADIUS_TLV, sizeof(caAPSetRadius_t), (BYTE *)ap_set_radius, aBuf);
    *aLen = 4 + sizeof(caAPSetRadius_t);

    printf("process cmd2\n");
    return TRUE;
}

int xcCmdProcApSet11nWireless(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caApSet11nWireless_t *set11nwireless = (caApSet11nWireless_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->intf, str, 15);
        }

        if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->name, str, 15);
        }
        if (strcasecmp(str, "sgi20") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->sgi20, str, 8);
        }
        if (strcasecmp(str, "spatial_tx_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->spatial_tx, str, 4);
        }
        if (strcasecmp(str, "spatial_rx_stream") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->spatial_rx, str, 4);
        }
        if (strcasecmp(str, "width") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(set11nwireless->width, str, 4);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_11N_WIRELESS_TLV, sizeof(caApSet11nWireless_t), (BYTE *)set11nwireless, aBuf);
    *aLen = 4 + sizeof(caApSet11nWireless_t);
    return TRUE;
}

int xcCmdProcApSetPmf(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caApSetPmf_t *setpmf = (caApSetPmf_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setpmf->intf, str, 15);
        }
        if (strcasecmp(str, "pmf") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setpmf->pmf, str, 15);
        }
    }

    wfaEncodeTLV(WFA_AP_SET_PMF_TLV, sizeof(caApSetPmf_t), (BYTE *)setpmf, aBuf);
    *aLen = 4 + sizeof(caApSetPmf_t);
    return TRUE;
}

int xcCmdProcApGetMacAddress(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caApGetMacAddress_t *getmac = (caApGetMacAddress_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(getmac->intf, str, 15);
        }

        if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(getmac->name, str, 16);
        }
    }

    wfaEncodeTLV(WFA_AP_GET_MAC_ADDRESS_TLV, sizeof(caApGetMacAddress_t), (BYTE *)getmac, aBuf);
    *aLen = 4 + sizeof(caApGetMacAddress_t);
    return TRUE;
}

int xcCmdProcApDeauthSta(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    caApDeauthSta_t *deauthsta = (caApDeauthSta_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(deauthsta->intf, str, 15);
        }
        if (strcasecmp(str, "name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(deauthsta->name, str, 15);
        }
        if (strcasecmp(str, "sta_mac_address") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(deauthsta->sta_mac_address, str, 17);
        }
        if (strcasecmp(str, "minorcode") == 0)
        {
            str                  = strtok_r(NULL, ",", &pcmdStr);
            deauthsta->MinorCode = atoi(str);
        }
    }

    wfaEncodeTLV(WFA_AP_DEAUTH_STA_TLV, sizeof(caApDeauthSta_t), (BYTE *)deauthsta, aBuf);
    *aLen = 4 + sizeof(caApDeauthSta_t);
    return TRUE;
}

#endif

int xcCmdProcStaBssidPool(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *disc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaBssidPool ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(disc->intf, str, 15);
        }
        if (strcasecmp(str, "bssid_filter") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncmp(str, "1", 1) == 0)
                disc->cmdsu.bssid_pool.enable = 1;
            else if (strncmp(str, "0", 1) == 0)
                disc->cmdsu.bssid_pool.enable = 0;
            else
                disc->cmdsu.bssid_pool.enable = -1;
        }
        if (strcasecmp(str, "bssid_list") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(disc->cmdsu.bssid_pool.bssid, str, WFA_BSSID_POOL_STR_LEN);
        }
    }

    wfaEncodeTLV(WFA_STA_BSSID_POOL_TLV, sizeof(dutCommand_t), (BYTE *)disc, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);
    return TRUE;
}

int xcCmdProcStaAddCredential(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setHS2 = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaAddCredential ...\n");

    setHS2->cmdsu.hs2_param.realm[0] = '\0';
    setHS2->cmdsu.hs2_param.mcc[0]   = '\0';
    setHS2->cmdsu.hs2_param.mnc[0]   = '\0';
    setHS2->cmdsu.hs2_param.prefer   = 0;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setHS2->intf);
        }
        if (strcasecmp(str, "type") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "uname_pwd") == 0)
                setHS2->cmdsu.hs2_param.cred = UNAME_PWD;
            else if (strcasecmp(str, "sim") == 0)
                setHS2->cmdsu.hs2_param.cred = SIM;
            else if (strcasecmp(str, "cert") == 0)
                setHS2->cmdsu.hs2_param.cred = CERT;
            DPRINT_INFO(WFA_OUT, "type is %s\n", str);
        }
        if (strcasecmp(str, "username") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.username, str, 128);
            DPRINT_INFO(WFA_OUT, "username is %s\n", str);
        }
        if (strcasecmp(str, "password") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.password, str, 128);
            DPRINT_INFO(WFA_OUT, "password is %s\n", str);
        }
        if (strcasecmp(str, "imsi") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.imsi, str, 17);
        }
        if (strcasecmp(str, "plmn_mcc") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.mcc, str, 4);
            setHS2->cmdsu.hs2_param.mcc[3] = '\0';
        }
        if (strcasecmp(str, "plmn_mnc") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.mnc, str, 4);
            setHS2->cmdsu.hs2_param.mnc[3] = '\0';
        }
        if (strcasecmp(str, "realm") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.realm, str, 128);
            DPRINT_INFO(WFA_OUT, "realm is %s\n", str);
        }
        if (strcasecmp(str, "root_ca") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.ca, str, 32);
            DPRINT_INFO(WFA_OUT, "root_ca is %s\n", str);
        }
        if (strcasecmp(str, "clientCertificate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setHS2->cmdsu.hs2_param.client, str, 32);
        }
        if (strcasecmp(str, "prefer") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncasecmp(str, "1", 1) == 0)
                setHS2->cmdsu.hs2_param.prefer = 1;
            /**
    str = strtok_r(NULL, ",", &pcmdStr);
    str[1]='\0';
    setHS2->cmdsu.hs2_param.prefer = atoi(str);
    **/
            DPRINT_INFO(WFA_OUT, "prefer is %s\n", str);
        }
        if (strcasecmp(str, "HOME_FQDN") == 0)
        {
            str                               = strtok_r(NULL, ",", &pcmdStr);
            setHS2->cmdsu.hs2_param.home_fdqn = 1;
            strncpy(setHS2->cmdsu.hs2_param.fqdn, str, 128);
        }
    }

    wfaEncodeTLV(WFA_STA_ADD_CREDENTIAL_TLV, sizeof(dutCommand_t), (BYTE *)setHS2, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcStaHS2Associate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaHS2Associate ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            strncpy(iface_for_policy_update, str, WFA_IF_NAME_LEN);
            DPRINT_INFO(WFA_OUT, "iface_for_policy_update %s\n", iface_for_policy_update);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);
        }
        if (strcasecmp(str, "ignore_blacklist") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncmp(str, "1", 1) == 0)
                setassoc->cmdsu.osu.ignore_blacklist = 1;
            else
                setassoc->cmdsu.osu.ignore_blacklist = 0;
        }
        if (strcasecmp(str, "osu") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncmp(str, "1", 1) == 0)
                setassoc->cmdsu.osu.enable = 1;
            else if (strncmp(str, "0", 1) == 0)
                setassoc->cmdsu.osu.enable = 0;
            else
                setassoc->cmdsu.osu.enable = -1;
        }
        if (strcasecmp(str, "osuSSID") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.osu.ssid, str, 128);
            DPRINT_INFO(WFA_OUT, "osu ssid is %s\n", str);
        }
        if (strcasecmp(str, "osuFriendlyName") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.osu.friendly_name, str, 128);
            DPRINT_INFO(WFA_OUT, "osu friendly_name is %s\n", str);
        }
    }

    wfaEncodeTLV(WFA_STA_HS2_ASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcStaHS2StaScan(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    char *str = NULL;
    dutCommand_t stascan;
    caStaScan_t *cascan = (caStaScan_t *)&stascan.cmdsu.Stascan_param;
    memset(&stascan, 0, sizeof(dutCommand_t));

    DPRINT_INFO(WFA_OUT, "Entering xcCmdProcStaHS2StaScan ...\n");
    if (aBuf == NULL)
        return WFA_FAILURE;

    memset(aBuf, 0, *aLen);
    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;
        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(stascan.intf, str, 15);
        }
    }
    wfaEncodeTLV(WFA_STA_HS2_STA_SCAN_TLV, sizeof(dutCommand_t), (BYTE *)&stascan, aBuf);
    *aLen = 4 + sizeof(stascan);
    return WFA_SUCCESS;
}

int xcCmdProcdevHS2Setparameter(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *cmd          = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    cadevSetParm_t *devsetparm = (cadevSetParm_t *)&cmd->cmdsu.sf;
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcdevHS2Setparameter ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(cmd->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", cmd->intf);
        }
        else if (strcasecmp(str, "program") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcasecmp(str, "HS2-R2") == 0 || strcasecmp(str, "HS2") == 0)
            {
                devsetparm->program = PROG_TYPE_HS2;
                for (;;)
                {
                    str = strtok_r(NULL, ",", &pcmdStr);
                    if (str == NULL || str[0] == '\0')
                        break;
                    if (strcasecmp(str, "Device") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        strncpy(devsetparm->devType, str, 10);
                        DPRINT_INFO(WFA_OUT, "devType is  %s\n", devsetparm->devType);
                    }
                    if (strcasecmp(str, "ClearARP") == 0)
                    {
                        str = strtok_r(NULL, ",", &pcmdStr);
                        if (strncasecmp(str, "1", 1) == 0)
                            devsetparm->hs2.clearARP = 1;
                        DPRINT_INFO(WFA_OUT, "ClearARP is %d\n", devsetparm->hs2.clearARP);
                    }
                }
            }
        }
    }

    wfaEncodeTLV(WFA_STA_HS2_DEV_SET_PARAMETER_TLV, sizeof(dutCommand_t), (BYTE *)cmd, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcStaOSU(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *setassoc = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaHS2Associate ...\n");

    setassoc->cmdsu.osu.enable                    = 1;
    setassoc->cmdsu.osu.prodESSAssoc              = 1;
    setassoc->cmdsu.osu.not_provide_friendly_name = 1;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", setassoc->intf);
        }
        if (strcasecmp(str, "osuFriendlyName") == 0)
        {
            setassoc->cmdsu.osu.not_provide_friendly_name = 0;
            str                                           = strtok_r(NULL, ",", &pcmdStr);
            strncpy(setassoc->cmdsu.osu.friendly_name, str, 128);
            DPRINT_INFO(WFA_OUT, "osu friendly_name is %s\n", str);
        }
        if (strcasecmp(str, "ProdESSAssoc") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strcmp(str, "0") == 0)
            {
                setassoc->cmdsu.osu.prodESSAssoc = 0;
            }
            DPRINT_INFO(WFA_OUT, "osu ProdESSAssoc is %s\n", str);
        }
    }
    wfaEncodeTLV(WFA_STA_HS2_ASSOCIATE_TLV, sizeof(dutCommand_t), (BYTE *)setassoc, aBuf);
    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcStaResetParm(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *ResetParm = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaResetParm ...\n");

    ResetParm->cmdsu.reset_parm.arp       = 0;
    ResetParm->cmdsu.reset_parm.HS2_cache = 0;

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(ResetParm->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", ResetParm->intf);
        }
        if (strcasecmp(str, "arp") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncmp(str, "all", 3) == 0)
                ResetParm->cmdsu.reset_parm.arp = 1;
            else if (strlen(str) != 0)
            {
                strncpy(ResetParm->cmdsu.reset_parm.ip, str, 16);
                /* copy IP */
            }
        }
        if (strcasecmp(str, "HS2_Cache_Profile") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            if (strncmp(str, "all", 3) == 0)
                ResetParm->cmdsu.reset_parm.HS2_cache = 1;
        }
    }

    wfaEncodeTLV(WFA_STA_RESET_PARM_TLV, sizeof(dutCommand_t), (BYTE *)ResetParm, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcStaPolicyUpdate(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *policyUpdate = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcStaPolicyUpdate ...\n");

    policyUpdate->cmdsu.staPolicyUpdate.policy_update = 0;
    policyUpdate->cmdsu.staPolicyUpdate.timeout       = 0;
    strcpy(policyUpdate->intf, iface_for_policy_update);
    DPRINT_INFO(WFA_OUT, "===iface_for_policy_update %s\n", iface_for_policy_update);
    DPRINT_INFO(WFA_OUT, "===policyUpdate->intf %s\n", policyUpdate->intf);

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "PolicyUpdate") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("str is %s\n", str);
            if (strcmp(str, "1") == 0)
            {
                policyUpdate->cmdsu.staPolicyUpdate.policy_update = 1;
            }
            DPRINT_INFO(WFA_OUT, "policy_update is %d\n", policyUpdate->cmdsu.staPolicyUpdate.policy_update);
        }
        if (strcasecmp(str, "timeout") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("str is %s\n", str);
            policyUpdate->cmdsu.staPolicyUpdate.timeout = atoi(str);
            DPRINT_INFO(WFA_OUT, "timeout is %d\n", policyUpdate->cmdsu.staPolicyUpdate.timeout);
        }
    }

    wfaEncodeTLV(WFA_STA_STA_POLICY_UPDATE, sizeof(dutCommand_t), (BYTE *)policyUpdate, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}

int xcCmdProcDevConfigureIe(char *pcmdStr, BYTE *aBuf, int *aLen)
{
    dutCommand_t *configIe = (dutCommand_t *)(aBuf + sizeof(wfaTLV));
    char *str;

    if (aBuf == NULL)
        return FALSE;

    memset(aBuf, 0, *aLen);

    DPRINT_INFO(WFA_OUT, "start xcCmdProcDevConfigureIe ...\n");

    for (;;)
    {
        str = strtok_r(NULL, ",", &pcmdStr);
        if (str == NULL || str[0] == '\0')
            break;

        if (strcasecmp(str, "interface") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strncpy(configIe->intf, str, 15);
            DPRINT_INFO(WFA_OUT, "interface %s\n", configIe->intf);
        }

        if (strcasecmp(str, "ie_name") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            strcpy(configIe->cmdsu.devConfigIe.ie_name, str);
            printf("ie_name is %s\n", str);
        }
        if (strcasecmp(str, "contents") == 0)
        {
            str = strtok_r(NULL, ",", &pcmdStr);
            printf("str is %s\n", str);
            strcpy(configIe->cmdsu.devConfigIe.ie_contents, str);
            printf("ie_content is %s\n", str);
        }
    }

    wfaEncodeTLV(WFA_STA_DEV_CONFIGURE_IE, sizeof(dutCommand_t), (BYTE *)configIe, aBuf);

    *aLen = 4 + sizeof(dutCommand_t);

    return TRUE;
}
