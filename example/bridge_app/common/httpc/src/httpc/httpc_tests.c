/** @file httpc_tests.c
 *
 * @brief This file provides CLI based tests for HTTP Client.
 *
 *  Copyright 2008-2020 NXP
 *
 *  NXP CONFIDENTIAL
 *  The source code contained or described herein and all documents related to
 *  the source code ("Materials") are owned by NXP, its suppliers and/or its
 *  licensors. Title to the Materials remains with NXP, its suppliers and/or its
 *  licensors. The Materials contain trade secrets and proprietary and
 *  confidential information of NXP, its suppliers and/or its licensors. The
 *  Materials are protected by worldwide copyright and trade secret laws and
 *  treaty provisions. No part of the Materials may be used, copied, reproduced,
 *  modified, published, uploaded, posted, transmitted, distributed, or
 *  disclosed in any way without NXP's prior express written permission.
 *
 *  No license under any patent, copyright, trade secret or other intellectual
 *  property right is granted to or conferred upon you by disclosure or delivery
 *  of the Materials, either expressly, by implication, inducement, estoppel or
 *  otherwise. Any license under such intellectual property rights must be
 *  express and approved by NXP in writing.
 *
 */

#include <cli.h>
#include <httpc.h>
#include <stdio.h>

static struct cli_command httpc_test_cmds[];

static void cmd_httpc_post(int argc, char **argv)
{
    if (argc < 3)
    {
        wmprintf("\nUsage: %s\n", httpc_test_cmds[0].help);
        return;
    }

    const char *url  = argv[1];
    const char *data = argv[2];
    int len          = strlen(data);
    int count        = 1; /* Default value */

    /* Check if user has given count */
    if (argc > 3)
    {
        count = strtol(argv[3], NULL, 0);
    }

    http_session_t hnd;
    int rv = http_open_session(&hnd, url, NULL);
    if (rv != 0)
    {
        wmprintf("Open session failed: %s (%d)", url, rv);
        return;
    }

    while (count--)
    {
        http_req_t req = {
            .type        = HTTP_POST,
            .resource    = url,
            .version     = HTTP_VER_1_1,
            .content     = data,
            .content_len = len,
        };

        rv = http_prepare_req(hnd, &req, (http_hdr_field_sel_t)(STANDARD_HDR_FLAGS | HDR_ADD_CONN_KEEP_ALIVE));
        if (rv != 0)
        {
            wmprintf("Prepare request failed: %d", rv);
            break;
        }

        rv = http_send_request(hnd, &req);
        if (rv != 0)
        {
            wmprintf("Send request failed: %d", rv);
            break;
        }

        http_resp_t *resp;
        rv = http_get_response_hdr(hnd, &resp);
        if (rv != 0)
        {
            wmprintf("Get resp header failed: %d", rv);
            break;
        }

        wmprintf("Content length: %d", resp->content_length);
        if (resp->content_length == 0)
        {
            continue;
        }

        wmprintf("------------Content------------");
        while (1)
        {
            char buf[32];
            rv = http_read_content(hnd, buf, sizeof(buf));
            if (rv == 0 || rv < 0)
            {
                break;
            }
            wmprintf("%s", buf);
        }

        if (rv < 0)
        {
            /* Error condition */
            break;
        }
    }
}

static struct cli_command httpc_test_cmds[] = {
    {"httpc-post", "httpc-post <url> <data string> [count]", cmd_httpc_post},
};

int httpc_test_cli_init()
{
    /* Register all the commands */
    if (cli_register_commands(&httpc_test_cmds[0], sizeof(httpc_test_cmds) / sizeof(struct cli_command)))
    {
        wmprintf("Unable to register CLI commands");
        while (1)
            ;
        /* do nothing -- stall */
    }

    return 0;
}
