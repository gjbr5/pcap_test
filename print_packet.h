#pragma once

#include <arpa/inet.h>
#include <pcap.h>
#include <stdio.h>

const int MAC_LEN = 6;
typedef struct eth_header
{
    uint8_t dmac[MAC_LEN];
    uint8_t smac[MAC_LEN];
    uint16_t type;
} eth_header;
const uint16_t ETH_TYPE_IP = 0x0800;

void print_mac(const u_char *mac);

const int IP_LEN = 4;
typedef struct ip_header
{
    unsigned int hdr_len : 4;
    unsigned int ver : 4;
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    unsigned int frag_offset1 : 5;
    unsigned int flag_mf : 1;
    unsigned int flag_df : 1;
    unsigned int flag_o : 1;
    unsigned int frag_offset2 : 8;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t hdr_cksum;
    uint8_t sip[IP_LEN];
    uint8_t dip[IP_LEN];
} ip_header;
const uint8_t IP_PROTOCOL_TCP = 6;

void print_ip(const u_char *ip);

typedef struct tcp_header
{
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_num;
    uint32_t ack_num;
    unsigned int reserved1 : 4;
    unsigned int hdr_len : 4;
    unsigned int fin : 1;
    unsigned int syn : 1;
    unsigned int rst : 1;
    unsigned int psh : 1;
    unsigned int ack : 1;
    unsigned int urg : 1;
    unsigned int reserved2 : 2;
    uint16_t win_size;
    uint16_t checksum;
    uint16_t urg_ptr;
} tcp_header;

void print_port(const u_char *port);

void print_packet(const u_char *packet, uint32_t caplen);
