/** @file healthmon_cli.c
 *
 *  @brief This file provides CLI for the healthmon
 *
 *  Copyright 2008-2023 NXP
 *
 *  SPDX-License-Identifier: BSD-3-Clause
 *
 */
#include <cli.h>
#include <healthmon.h>

#include "healthmon_int.h"

static void cmd_healthmon_stat(int argc, char **argv)
{
    healthmon_display_stat();
}

static struct cli_command healthmon_cmds[] = {
    {"healthmon-stat", "", cmd_healthmon_stat},
};

int healthmon_cli_init(void)
{
    return cli_register_command(&healthmon_cmds[0]);
}
