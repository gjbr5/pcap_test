#include "print_packet.h"

void print_mac(const uint8_t *mac)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

void print_ip(const uint8_t *ip)
{
    printf("%d.%d.%d.%d\n", ip[0], ip[1], ip[2], ip[3]);
}

void print_port(const uint16_t port)
{
    printf("%d\n", ntohs(port));
}

void print_packet(const u_char *packet, uint32_t caplen)
{
    const eth_header *eth;
    const ip_header *ip;
    const tcp_header *tcp;
    const u_char *data;

    eth = reinterpret_cast<const eth_header *>(packet);

    if (ntohs(eth->type) == ETH_TYPE_IP)
        ip = reinterpret_cast<const ip_header *>(packet + sizeof(eth_header));
    else
        return;

    if (ntohs(ip->protocol == IP_PROTOCOL_TCP))
        tcp = reinterpret_cast<const tcp_header *>(reinterpret_cast<const u_char *>(ip)
                                                   + ip->hdr_len * 4);
    else
        return;

    data = reinterpret_cast<const u_char *>(tcp) + tcp->hdr_len * 4;
    int data_len = ntohs(ip->tot_len) - ip->hdr_len * 4 - tcp->hdr_len * 4;

    if (data_len < 1)
        return;

    printf("%u bytes captured\n", caplen);
    printf("ip header : %d bytes\n", ip->hdr_len * 4);
    printf("tcp header : %d bytes\n", tcp->hdr_len * 4);
    printf("data length : %d bytes\n", data_len);

    printf("dmac : ");
    print_mac(eth->dmac);
    printf("smac : ");
    print_mac(eth->smac);

    printf("sip : ");
    print_ip(ip->sip);
    printf("dip : ");
    print_ip(ip->dip);

    printf("sport : ");
    print_port(tcp->sport);
    printf("dport : ");
    print_port(tcp->dport);

    printf("data : ");
    for (int i = 0; i < data_len && i < 10; i++)
        printf("%02x ", data[i]);
    printf("\n\n");
}
