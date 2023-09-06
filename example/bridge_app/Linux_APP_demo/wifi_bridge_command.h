#include<stdio.h>
#include<stdlib.h>
#include<stdint.h>

#pragma pack(1)           //unalign
typedef struct BRIDGE_COMMAND
{
    uint16_t  cmd;
    uint16_t size;
    uint8_t Seqnum;
    uint8_t bss;
    uint16_t result;
    uint8_t action;
}W_CMD, W_RES;

typedef struct TLVTypeHeader_t
{
    uint8_t  type;
    uint16_t size;
}TypeHeader_t;

typedef struct SSID_ParaSet
{
    TypeHeader_t header;
    uint8_t ssid[1];
}SSID_tlv;

typedef struct PING_ParaSet
{
    TypeHeader_t header;
    uint16_t packet_count;
    uint8_t ping_ip[1];
}PING_tlv;

typedef struct IPERF_ParaSet
{
    TypeHeader_t header;
    uint16_t time;
    uint8_t iperf_ip[1];
}IPERF_tlv;

typedef struct CONNECT_RES
{
    TypeHeader_t header;
    uint8_t ip[16];
    uint8_t ssid[32];
}CONNECT_res_tlv;

typedef struct SCAN_NETWORK_INFO
{
    uint8_t mac[6];
    uint8_t ssid[32];
    uint8_t channel;
    uint8_t rssi;
    uint8_t security;
}scan_network_info;

typedef struct SCAN_RES
{
    TypeHeader_t header;
    uint8_t network_count;
    scan_network_info netinfo[20];
}SCAN_res_tlv;

typedef struct PING_RES
{
    TypeHeader_t header;
    uint8_t status;
    uint32_t packet_transmit;
    uint32_t packet_received;
}PING_res_tlv;

typedef struct IPERF_INFO
{
    uint8_t  role;
    uint8_t  local_addr[4];
    uint16_t local_port;
    uint8_t  remote_addr[4];
    uint16_t remote_port;
    uint64_t bytes_transferred;
    uint32_t ms_duration;
    uint32_t bandwidth_Mbitpsec;
}IPERF_info;

typedef struct IPERF_RES
{
    TypeHeader_t header;
    IPERF_info iperf_info;
}IPERF_res_tlv;

#pragma pack()

#define BRIDGE_COMMAND_LEN 9
#define TLV_HEADER_LEN 3

/*Convert IP Adderss to hexadecimal*/
int IP_to_hex(char* IPstr, uint8_t *hex);

uint16_t string_to_decimal(uint8_t *x ,uint8_t len);

void wlan_input_to_string(char *arg);

/*Prase command*/
int string_to_command(char *strcom);

/*wifi_bridge command usage*/
void wlan_bridge_command_print();

/*'wlan-scan' usage*/
void wlan_scan_usage_dump();

/*'wlan-connect' usage*/
void wlan_connect_usage_dump();

/*'wlan-disconnect' usage*/
void wlan_disconnect_usage_dump();

/*'ping' usage*/
void wlan_ping_usage_dump();

/*'iperf' usage*/
void wlan_iperf_usage_dump();

int wlan_scan_command();

int wlan_connect_command(char *arg);

int wlan_get_connect_res_command();

int wlan_disconnect_command();

int wlan_ping_command();

int wlan_get_scan_res_command();

int wlan_get_ping_res_command();

int wlan_iperf_command();

int wlan_get_iperf_res_command();

int wlan_process_response(uint8_t *res);

int wlan_process_discon_response(uint8_t *res);

int wlan_process_con_response(uint8_t *res);

void print_security_mode(uint8_t sec);

int wlan_process_scan_response(uint8_t *res);

int wlan_process_ping_response(uint8_t *res);

int wlan_process_iperf_response(uint8_t *res);
