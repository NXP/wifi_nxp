#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<wifi_bridge_command.h>
#include<wifi_bridge_app.h>

extern uint8_t command[200];
uint8_t wlan_commands[9][20] = {"wlan-scan","wlan-connect","wlan-disconnect","ping","iperf","get-connect-result","get-scan-result","get-ping-result","get-iperf-result"};
char in_str[15][30]; 
int count_str = 0;

/**
 * @brief       Judge whether a string can be converted to a decimal number
 * 
 * @param x     A pointer to uint8_t
 * @param len   Length
 * @return      If x can be converted to a decimal number : TRUE, else : FALSE
 */
int str_is_decimal(uint8_t *x ,uint8_t len)
{
    for(int i = 0; i < len; i++)
        if(x[i] < '0' || x[i] > '9')
        {
            printf("Invalid decimal format!\r\n");
            return FALSE;
        }
    return TRUE;
}

/**
 * @brief        Convert a string to decimal number
 * 
 * @param x      A pointer to uint_8
 * @param len    Length
 * @return       Decimal number converted from string
 */
uint16_t string_to_decimal(uint8_t *x ,uint8_t len)
{
    uint8_t temp = 0, i, j = 0;
    uint16_t res = 0;
    int POW;
    for(i = 0; i < len; i++)
    {
        POW = 1;
        for(int k = 1; k < len - i; k++)
        { 
            POW = POW * 10;
        }
        res += (x[i] - '0') * POW;
    }
    return res;
}

/**
 * @brief         Convert IP string to hex IP
 * 
 * @param IPstr   A pointer to char
 * @param hex     A pointer to uint8_t
 * @return        If IPstr can be converted hex IP: TRUE, else : False
 */
int IP_to_hex(char* IPstr, uint8_t *hex)
{
    int len, temp;
    len = strlen(IPstr);
    for(int i = 0; i < len; i++)
    {
        if(IPstr[i] == '.')
            hex[i] = '.';
        else if(IPstr[i] >= '0' && IPstr[i] <= '9')
            hex[i] = IPstr[i];
        else
        {
            printf("Please input the correct IP address!\r\n");
            return FALSE;
        }
    }
    return TRUE;
}

/**
 * @brief       Store the command in in_str
 * 
 * @param arg   A pointer to char
 */
void wlan_input_to_string(char *arg)
{
    int len = strlen(arg);
    int i = 0;
    char temp[30];
    for(; i < len; )
    {
        if((arg[i] >= '0' && arg[i] <= '9') || (arg[i] >= 'a' && arg[i] <= 'z'))
        {
            int j = 0;
            while (arg[i] != ' ')
            {
                in_str[count_str][j] = arg[i];
                i++;
                j++;
                if(i == len)
                    break;
            }
            in_str[count_str][j] = '\0';
            count_str++;
        }
        else
        {
            i++;
        }
    }
}

/**
 * @brief          Prase command and call corresponding functions
 * 
 * @param strcom   A pointer to char
 * @return         return process status
 */
int string_to_command(char* strcom)
{
    int len = strlen(strcom);
    char *temp = strcom;
    if(!strncmp(strcom, wlan_commands[0], strlen(wlan_commands[0])))
        return wlan_scan_command();
    else if(!strncmp(strcom, wlan_commands[1], strlen(wlan_commands[1])))
    {
        if(strlen(strcom) <= strlen(wlan_commands[1])) // If you input "wlan-connect" ,the length of input is 1 longer than wlan_command[1]
        {
            wlan_connect_usage_dump();
            return FALSE;
        }
        return wlan_connect_command(temp + strlen(wlan_commands[1]));
    }
    else if(!strncmp(strcom, wlan_commands[2], strlen(wlan_commands[2])))
        return wlan_disconnect_command();
    else if(!strncmp(strcom, wlan_commands[3], strlen(wlan_commands[3])))
    {
        if(strlen(strcom) <= strlen(wlan_commands[3]))
        {
            wlan_ping_usage_dump();
            return FALSE;
        }
        count_str = 0;
        wlan_input_to_string(temp + strlen(wlan_commands[3]));
        return wlan_ping_command();
    }
    else if(!strncmp(strcom, wlan_commands[4], strlen(wlan_commands[4])))
    {
        if(strlen(strcom) <= strlen(wlan_commands[4]))
        {
            wlan_iperf_usage_dump();
            return FALSE;
        }
        count_str = 0;
        wlan_input_to_string(temp + strlen(wlan_commands[4]));
        return wlan_iperf_command();
    }
    else if(!strncmp(strcom, wlan_commands[5], strlen(wlan_commands[5])))
    {
        return wlan_get_connect_res_command();
    }
    else if(!strncmp(strcom, wlan_commands[6], strlen(wlan_commands[6])))
    {
        return wlan_get_scan_res_command();
    }
    else if(!strncmp(strcom, wlan_commands[7], strlen(wlan_commands[7])))
    {
        return wlan_get_ping_res_command();
    }
    else if(!strncmp(strcom, wlan_commands[8], strlen(wlan_commands[8])))
    {
        return wlan_get_iperf_res_command();
    }
    else
    {
        printf("Please input correct command!\r\n");
        wlan_bridge_command_print();
        return FALSE;
    }
}

/**
 * @brief Commands supported by this APP
 * 
 */
void wlan_bridge_command_print()
{
    printf("============================================================\r\n");
    printf("wlan-scan:\r\n");
    printf("Scan networks\r\n");
    printf("get-scan-result:\r\n");
    printf("get scanned networks result\r\n");
    printf("wlan-connect:\r\n");
    printf("wlan-connect <ssid>\r\n");
    printf("Connect to open mode AP and ssid only supports uint8_tacters and numbers.\r\n");
    printf("get-connect-result:\r\n");
    printf("get ssid and ip address of connected network\r\n");
    printf("wlan-disconnect:\r\n");
    printf("Disconnect from the network you are connecting to\r\n");
    printf("ping:\r\n");
    printf("ping [c <IP Address>\r\n");
    printf("ping [c <packet_count>] <IP Address>\r\n");
    printf("get-ping-result:\r\n");
    printf("get result of ping process\r\n");
    printf("iperf:\r\n");
    printf("iperf s                             TCP Server\r\n");
    printf("iperf su                            UDP Server\r\n");
    printf("iperf c <IP Address>  t <time>      TCP Client\r\n");
    printf("iperf cu <IP Address> t <time>      UDP Client\r\n");
    printf("iperf a                             Iperf Abort\r\n");
    printf("get-iperf-result:\r\n");
    printf("get result of iperf process\r\n");
    printf("============================================================\r\n");
}

/**
 * @brief 'wlan-scan' Usage
 * 
 */
void wlan_scan_usage_dump()
{
    printf("Usage: \r\n");
    printf("wlan-scan\r\n");
}

/**
 * @brief 'wlan-connect' Usage
 * 
 */
void wlan_connect_usage_dump()
{
    printf("Usage: \r\n");
    printf("wlan-connect <ssid>\r\n");
}

/**
 * @brief 'wlan-disconnect' Usage
 * 
 */
void wlan_disconnect_usage_dump()
{
    printf("Usage: \r\n");
    printf("wlan-disconnect\r\n");
}

/**
 * @brief 'ping' Usage
 * 
 */
void wlan_ping_usage_dump()
{
    printf("Usage: \r\n");
    printf("ping [c <packet_count>] <IP Address>\r\n");
}

/**
 * @brief 'iperf' Usage
 * 
 */
void wlan_iperf_usage_dump()
{
    printf("iperf:\r\n");
    printf("iperf s                             TCP Server\r\n");
    printf("iperf su                            UDP Server\r\n");
    printf("iperf c <IP Address>  t <time>      TCP Client\r\n");
    printf("iperf cu <IP Address> t <time>      UDP Client\r\n");
    printf("iperf a                             Iperf Abort\r\n");
}

/**
 * @brief This function prepares scan command
 * 
 * @return Status returned
 */
int wlan_scan_command()
{
    W_CMD *scan_command = (W_CMD *)command;
    scan_command->cmd = 0x01;
    scan_command->size = 0x09;
    scan_command->Seqnum = 0x00;
    scan_command->bss = 0x00;
    scan_command->result = 0x00;
    scan_command->action = 0x01;
    return TRUE;
}

/**
 * @brief  This function prepares command to get scan result
 * 
 * @return status returned
 */
int wlan_get_scan_res_command()
{
    W_CMD *connect_res_command = (W_CMD *)command;
    connect_res_command->cmd = 0x01;
    connect_res_command->Seqnum = 0x00;
    connect_res_command->bss = 0x00;
    connect_res_command->result = 0x00;
    connect_res_command->action = 0x00;
    connect_res_command->size = BRIDGE_COMMAND_LEN;
    return TRUE;
}

/**
 * @brief      This function prepares connect command and append ssid tlv
 * 
 * @param arg  A pointer to bridge command structure
 * @return     status returned
 */
int wlan_connect_command(char *arg)
{
    W_CMD *connect_command = (W_CMD *)command;
    int len = strlen(arg);
    uint8_t *tlv = NULL;
    int i = 0;
    connect_command->cmd = 0x02;
    connect_command->Seqnum = 0x00;
    connect_command->bss = 0x00;
    connect_command->result = 0x00;
    connect_command->action = 0x01;

    tlv = command + BRIDGE_COMMAND_LEN;
    SSID_tlv *ssid_tlv = (SSID_tlv *) tlv;
    ssid_tlv->header.type = 0x02;
    uint16_t k = 0;
    while (arg[i] == ' ')
    {
        i++;
        if(i >= len)
        {
            wlan_connect_usage_dump();
            return FALSE;
        }
    }
    for(i; i < len; i++)
    {
        ssid_tlv->ssid[k] = arg[i];
        ++k;
    }
    ssid_tlv->header.size = k;
    connect_command->size = BRIDGE_COMMAND_LEN + TLV_HEADER_LEN + ssid_tlv->header.size;
    return TRUE;
}

/**
 * @brief  This functions prepares command to get connect result
 * 
 * @return Status returned
 */
int wlan_get_connect_res_command()
{
    W_CMD *connect_res_command = (W_CMD *)command;
    connect_res_command->cmd = 0x02;
    connect_res_command->Seqnum = 0x00;
    connect_res_command->bss = 0x00;
    connect_res_command->result = 0x00;
    connect_res_command->action = 0x00;
    connect_res_command->size = BRIDGE_COMMAND_LEN;
    return TRUE;
}

/**
 * @brief  This function prepares disconnect command
 * 
 * @return Status returned
 */
int wlan_disconnect_command()
{
    W_CMD *disconnect_command = (W_CMD *)command;
    disconnect_command->cmd = 0x03;
    disconnect_command->size = 0x09;
    disconnect_command->Seqnum = 0x00;
    disconnect_command->bss = 0x00;
    disconnect_command->result = 0x00;
    disconnect_command->action = 0x01;

    return TRUE;
}

/**
 * @brief  This function prepares ping command
 * 
 * @return Status returned
 */
int wlan_ping_command()
{
    W_CMD *ping_command = (W_CMD *)command;
    ping_command->cmd = 0x04;
    ping_command->Seqnum = 0x00;
    ping_command->bss = 0x00;
    ping_command->result = 0x00;
    ping_command->action = 0x01;
    ping_command->size = BRIDGE_COMMAND_LEN;
    int i = 0;

    PING_tlv *ping_tlv = (PING_tlv *) (command + BRIDGE_COMMAND_LEN);
    ping_tlv->header.type = 0x04;
    ping_tlv->packet_count = 0x00;
    ping_tlv->header.size = 0x02;
    do
    {
        if(in_str[i][0] == 'c')
        {
            if(i == count_str -1)
            {
                wlan_ping_usage_dump();
                return FALSE;
            }
            else
            {
                int packet_len = strlen(in_str[i + 1]);
                int ret = str_is_decimal(in_str[i + 1], packet_len);
                if(ret == FALSE)
                {
                    wlan_ping_usage_dump();
                    return FALSE;
                }
                ping_tlv->packet_count = string_to_decimal(in_str[i + 1], packet_len);
                i += 2;
            }
        }
        else if(in_str[i][0] >= '0' && in_str[i][0] <= '9')
        {
            int ret = IP_to_hex(in_str[i], ping_tlv->ping_ip);
            if(ret == FALSE)
            {
                wlan_ping_usage_dump();
                return FALSE;
            }
            ping_tlv->header.size += strlen(in_str[i]);
            i++;
        }

    } while (i < count_str);
    ping_command->size += (ping_tlv->header.size + TLV_HEADER_LEN);

    return TRUE;    
}

/**
 * @brief  This function prepares command to get ping result
 * 
 * @return Status returned
 */
int wlan_get_ping_res_command()
{
    W_CMD *ping_command = (W_CMD *)command;
    ping_command->cmd = 0x04;
    ping_command->Seqnum = 0x00;
    ping_command->bss = 0x00;
    ping_command->result = 0x00;
    ping_command->action = 0x00;
    ping_command->size = BRIDGE_COMMAND_LEN;

    return TRUE;
}

/**
 * @brief  This function prepares iperf command
 * 
 * @return Status returned
 */
int wlan_iperf_command()
{
    W_CMD *iperf_command = (W_CMD *)command;
    iperf_command->cmd = 0x05;
    iperf_command->Seqnum = 0x00;
    iperf_command->bss = 0x00;
    iperf_command->result = 0x00;
    iperf_command->action = 0x01;
    iperf_command->size = BRIDGE_COMMAND_LEN;

    uint8_t *tlv = command + BRIDGE_COMMAND_LEN;
    IPERF_tlv *iperf_tlv = (IPERF_tlv *)tlv;
    char IPERF[6][3]={"s","su","c","cu","t","a"}; 
    iperf_tlv->header.size = 2;
    iperf_tlv->header.type = 0;
    iperf_tlv->time = 0;
    int i = 0;

    do
    {
        if(in_str[i][0] == IPERF[0][0] && strlen(in_str[i]) == 1)    //iperf s     TCP server
        {
            iperf_tlv->header.type = 0x51;
            iperf_tlv->header.size = 0x00;
            break;
        }
        else if(in_str[i][0] == IPERF[1][0] && in_str[i][1] == IPERF[1][1])             // iperf su     UDP server
        {
            iperf_tlv->header.type = 0x52;
            iperf_tlv->header.size = 0x00;
            break;
        }
        else if(in_str[i][0] == IPERF[2][0] && strlen(in_str[i]) == 1)     //iperf c   TCP client
        {
            iperf_tlv->header.type = 0x53;
            int ret = IP_to_hex(in_str[i + 1], iperf_tlv->iperf_ip);
            if(ret == FALSE)
            {
                wlan_iperf_usage_dump();
                return FALSE;
            }
            iperf_tlv->header.size += strlen(in_str[i + 1]);
            i += 2;
        }
        else if(in_str[i][0] == IPERF[3][0] && in_str[i][1] == IPERF[3][1])                 //iperf cu  UDP Client
        {
            iperf_tlv->header.type = 0x54;
            int ret = IP_to_hex(in_str[i + 1], iperf_tlv->iperf_ip);
            if(ret == FALSE)
            {
                wlan_iperf_usage_dump();
                return FALSE;
            }
            iperf_tlv->header.size += strlen(in_str[i + 1]);
            i += 2;
        }
        else if(in_str[i][0] == IPERF[4][0])                      // t time
        {
            int ret = str_is_decimal(in_str[i + 1], strlen(in_str[i + 1]));
            if(ret == FALSE)
            {
                wlan_iperf_usage_dump();
                return FALSE;
            }
            iperf_tlv->time = string_to_decimal(in_str[i + 1], strlen(in_str[i + 1]));
            i += 2;
        }
        else if(in_str[i][0] == IPERF[5][0])
        {
            iperf_tlv->header.type = 0x55;
            iperf_tlv->header.size = 0x00;
            break;
        }
        else
            i++;
    } while (i < count_str);
    
    if(iperf_tlv->header.type == 0)
    {
        wlan_iperf_usage_dump();
        return FALSE;
    }
    iperf_command->size += (TLV_HEADER_LEN + iperf_tlv->header.size);

    return TRUE;
}

/**
 * @brief  This function prepares command to get iperf result
 * 
 * @return Status returned
 */
int wlan_get_iperf_res_command()
{
    W_CMD *ping_command = (W_CMD *)command;
    ping_command->cmd = 0x05;
    ping_command->Seqnum = 0x00;
    ping_command->bss = 0x00;
    ping_command->result = 0x00;
    ping_command->action = 0x00;
    ping_command->size = BRIDGE_COMMAND_LEN;

    return TRUE;
}

/**
 * @brief       This function processes response from bridge_app
 * 
 * @param res   A pointer to uint8_t 
 * @return      Status returned
 */
int wlan_process_response(uint8_t *res)
{
    int ret;
    W_RES * cmd_res = (W_RES *)res;
    if(cmd_res->cmd == 0x01)
        ret = wlan_process_scan_response(res);
    else if(cmd_res->cmd == 0x02)
        ret = wlan_process_con_response(res);
    else if(cmd_res->cmd == 0x03)
        ret = wlan_process_discon_response(res);
    else if(cmd_res->cmd == 0x04)
        ret = wlan_process_ping_response(res);
    else if(cmd_res->cmd == 0x05)
        ret = wlan_process_iperf_response(res);
    return ret;
}

/**
 * @brief       This function processes connect response from bridge_app
 * 
 * @param res   A pointer to uint8_t
 * @return      Status returned
 */
int wlan_process_con_response(uint8_t *res)
{
    W_RES * cmd_res = (W_RES *)res;
    if(cmd_res->result == 0x00 && cmd_res->size > BRIDGE_COMMAND_LEN)
    {
        CONNECT_res_tlv *connect_res_tlv = (CONNECT_res_tlv *)(res + BRIDGE_COMMAND_LEN);
        printf("Already connected to an AP:\r\n");
        printf("SSID = {%s}\r\n",connect_res_tlv->ssid);
        printf("IPv4 Address: {%s}\r\n",connect_res_tlv->ip);
    }
    else
    {
        printf("Failed to get correct AP info!\r\n");
        printf("Please input 'wlan-connect <ssid>' to connect an AP or wait a few moments for the AP information.\r\n");
    }
    return TRUE;
}

/**
 * @brief      This function processes disconnect response from bridge_app
 * 
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_discon_response(uint8_t *res)
{
    W_RES * cmd_res = (W_RES *)res;
    if(cmd_res->result == 0x00)
        printf("Already disconnect to network.\r\n");
    else
        printf("Failed to disconnect to network.\r\n");
}

/**
 * @brief     This function prases scan security mode from scan response
 * 
 * @param sec security
 */
void print_security_mode(uint8_t sec)
{
    char security[7][20] = {"WEP","WPA/WPA2 Mixed","WPA","WPA2","WPA3 SAE","WPA2 Enterprise","OPEN"};
    switch (sec)
    {
    case 1:
        printf("security: %s\r\n",security[0]);
        break;
    case 2:
        printf("security: %s\r\n",security[1]);
        break;
    case 3:
        printf("security: %s\r\n",security[2]);
        break;
    case 4:
        printf("security: %s\r\n",security[3]);
        break;
    case 5:
        printf("security: %s\r\n",security[4]);
        break;
    case 6:
        printf("security: %s\r\n",security[5]);
        break;
    case 7:
        printf("security: %s\r\n",security[6]);
        break;
    default:
        break;
    }
}

/**
 * @brief      This function processes scan response from bridge_app
 * 
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_scan_response(uint8_t *res)
{
    W_RES * cmd_res = (W_RES *)res;
    int ret;
    if(cmd_res->result == 0x00)
    {
        SCAN_res_tlv *scan_res_tlv = (SCAN_res_tlv *)(res + BRIDGE_COMMAND_LEN);
        uint8_t count = scan_res_tlv->network_count;
        char ssid[32];
        if(count == 0)
        {
            printf("no networks found\r\n");
        }
        else
        {
            printf("%d networks found\r\n",count);
            for(int i = 0; i < count; i++)
            {
                printf("%02x:%02x:%02x:",scan_res_tlv->netinfo[i].mac[0],scan_res_tlv->netinfo[i].mac[1],scan_res_tlv->netinfo[i].mac[2]);
                printf("%02x:%02x:%02x ",scan_res_tlv->netinfo[i].mac[3],scan_res_tlv->netinfo[i].mac[4],scan_res_tlv->netinfo[i].mac[5]);
                printf("[%s]\r\n",scan_res_tlv->netinfo[i].ssid);
                printf("channel: %d\r\n",scan_res_tlv->netinfo[i].channel);
                printf("rssi: -%d dBm\r\n",scan_res_tlv->netinfo[i].rssi);
                print_security_mode(scan_res_tlv->netinfo[i].security);
                printf("\r\n");
            }
        }
    }
    else
    {
        printf("Please input 'wlan-scan'.\r\n");
        printf("Wait a moment and input 'get-scan-result' to get the scan result.\r\n");
    }
    return TRUE;
}

/**
 * @brief      This function processes ping response from bridge_app
 * 
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_ping_response(uint8_t *res)
{
    W_RES * cmd_res = (W_RES *)res;
    if(cmd_res->result == 0x00)
    {
        PING_res_tlv *ping_res_tlv = (PING_res_tlv *)(res + BRIDGE_COMMAND_LEN);
        if(ping_res_tlv->status == 0)
            printf("The PING process is not over yet, please try again later...\r\n");
        else
        {
            int loss_rate = ((ping_res_tlv->packet_transmit - ping_res_tlv->packet_received) * 100)/ping_res_tlv->packet_transmit;
            printf("---  ping statistics  ---\r\n");
            printf("%d packets transmitted, %d packets received, %d%% packets loss\r\n",ping_res_tlv->packet_transmit,ping_res_tlv->packet_received,loss_rate);
        }
    }
    else
        printf("Please input 'ping <ip>' and 'get-ping-result' to get ping result.\r\n");
    return TRUE;
}

/**
 * @brief      This function processes iperf response from bridge_app
 * 
 * @param res  A pointer to uint8_t
 * @return     Status returned
 */
int wlan_process_iperf_response(uint8_t *res)
{
    W_RES * cmd_res = (W_RES *)res;
    if(cmd_res->result == 0x00)
    {
        IPERF_res_tlv *iperf_res_tlv = (IPERF_res_tlv *)(res + BRIDGE_COMMAND_LEN);
        printf("------------------------\r\n");
        if(iperf_res_tlv->iperf_info.role == 0x11)
            printf("TCP_DONE_CLIENT (TX)\r\n");
        else if(iperf_res_tlv->iperf_info.role == 0x12)
            printf("TCP_DONE_SERVER (RX)\r\n");
        else if(iperf_res_tlv->iperf_info.role == 0x21)
            printf("UDP_DONE_CLIENT (TX)\r\n");
        else if(iperf_res_tlv->iperf_info.role == 0x22)
            printf("UDP_DONE_CLIENT (RX)\r\n");
        else
        {
            printf("ABORT_LOCAL\r\n");
            return TRUE;
        }
        
        printf("Local address : %u.%u.%u.%u  Port : %d\r\n",iperf_res_tlv->iperf_info.local_addr[0],iperf_res_tlv->iperf_info.local_addr[1],
        iperf_res_tlv->iperf_info.local_addr[2],iperf_res_tlv->iperf_info.local_addr[3],iperf_res_tlv->iperf_info.local_port);
        printf("Remote address : %u.%u.%u.%u Port : %d\r\n",iperf_res_tlv->iperf_info.remote_addr[0],iperf_res_tlv->iperf_info.remote_addr[1],
        iperf_res_tlv->iperf_info.remote_addr[2],iperf_res_tlv->iperf_info.remote_addr[3],iperf_res_tlv->iperf_info.remote_port);
        printf("Bytes Transferred %ld\r\n",iperf_res_tlv->iperf_info.bytes_transferred);
        printf("Duration (ms) %d\r\n",iperf_res_tlv->iperf_info.ms_duration);
        printf("BandWidth (Mbit/sec) %d\r\n",iperf_res_tlv->iperf_info.bandwidth_Mbitpsec);
    }
    else
        printf("Failed to get iperf result!\r\n");
    return TRUE;
}