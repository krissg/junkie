#ifndef TCP_H
#define TCP_H


#ifdef __cplusplus
extern "C" {
#endif

#include <linux/if_ether.h>

#define ETHERTYPE_IPV4          0x0800
#define ETHERTYPE_IPV6          0x86dd
#define ETHERTYPE_VLAN          0x8100
#define ETHERTYPE_ARP           0x0806


#define IP_MF                   0x2000
#define IP_DF                   0x4000

/* ETHERNET HEADER OFFSETS */
#define ETHER_DST_ADDR_OFFSET   0
#define ETHER_SRC_ADDR_OFFSET   ETHER_DST_ADDR_OFFSET + ETH_ALEN
#define ETHER_ETHERTYPE_OFFSET  ETHER_SRC_ADDR_OFFSET + ETH_ALEN

// #define ETHER_HEADER_SIZE       ETHER_ETHERTYPE_OFFSET + sizeof(uint16_t) + 2
#define ETHER_HEADER_SIZE       ETHER_ETHERTYPE_OFFSET + sizeof(uint16_t)


/* ARP HEADER OFFSETS */
#define ARP_HTYPE_OFFSET        0
#define ARP_PTYPE_OFFSET        ARP_HTYPE_OFFSET + sizeof(uint16_t)
#define ARP_HLEN_OFFSET         ARP_PTYPE_OFFSET + sizeof(uint16_t)
#define ARP_PLEN_OFFSET         ARP_HLEN_OFFSET + sizeof(uint8_t)
#define ARP_OPER_OFFSET         ARP_PLEN_OFFSET + sizeof(uint8_t)
#define ARP_SHA_OFFSET          ARP_OPER_OFFSET + sizeof(uint16_t)


/* IPv4 HEADER OFFSETS */
#define IPV4_HLEN_OFFSET        0
#define IPV4_VERSION_OFFSET     0
#define IPV4_TOS_OFFSET         IPV4_VERSION_OFFSET + sizeof(uint8_t)
#define IPV4_LEN_OFFSET         IPV4_TOS_OFFSET + sizeof(uint8_t)
#define IPV4_ID_OFFSET          IPV4_LEN_OFFSET + sizeof(uint16_t)
#define IPV4_OFF_OFFSET         IPV4_ID_OFFSET + sizeof(uint16_t)
#define IPV4_TTL_OFFSET         IPV4_OFF_OFFSET + sizeof(uint16_t)
#define IPV4_PROTO_OFFSET       IPV4_TTL_OFFSET + sizeof(uint8_t)
#define IPV4_CHECKSUM_OFFSET    IPV4_PROTO_OFFSET + sizeof(uint8_t)
#define IPV4_SRC_HOST_OFFSET    IPV4_CHECKSUM_OFFSET + sizeof(uint16_t)
#define IPV4_DST_HOST_OFFSET    IPV4_SRC_HOST_OFFSET + sizeof(uint32_t)


/* IPv6 HEADER OFFSETS */
#define IPV6_HLEN               40 /* defined as a constant in the protocol */

#define IPV6_HLEN_OFFSET        0
#define IPV6_TRAFFIC_OFFSET     0
#define IPV6_FLOW_LABEL_OFFSET  0
#define IPV6_PAYLOAD_LEN_OFFSET IPV6_HLEN_OFFSET + sizeof(uint32_t)
#define IPV6_NEXT_HDR_OFFSET    IPV6_PAYLOAD_LEN_OFFSET + sizeof(uint16_t)
#define IPV6_HOP_LIMIT_OFFSET   IPV6_NEXT_HDR_OFFSET + sizeof(uint8_t)
#define IPV6_SRC_HOST_OFFSET    IPV6_HOP_LIMIT_OFFSET + sizeof(uint8_t)
#define IPV6_DST_HOST_OFFSET    IPV6_SRC_HOST_OFFSET + sizeof(struct in6_addr)


/* TCP HEADER OFFSETS */
#define TCP_SRC_PORT_OFFSET     0
#define TCP_DST_PORT_OFFSET     TCP_SRC_PORT_OFFSET + sizeof(uint16_t)
#define TCP_SEQ_OFFSET          TCP_DST_PORT_OFFSET + sizeof(uint16_t)
#define TCP_ACK_NUM_OFFSET      TCP_SEQ_OFFSET + sizeof(uint32_t)
#define TCP_RES_OFFSET          TCP_ACK_NUM_OFFSET + sizeof(uint32_t)
#define TCP_DATA_OFF_OFFSET     TCP_RES_OFFSET
#define TCP_FLAGS_OFFSET        TCP_DATA_OFF_OFFSET + sizeof(uint8_t)
#define TCP_WINDOW_OFFSET       TCP_FLAGS_OFFSET + sizeof(uint8_t)
#define TCP_CHECKSUM_OFFSET     TCP_WINDOW_OFFSET + sizeof(uint16_t)
#define TCP_URG_PTR_OFFSET      TCP_CHECKSUM_OFFSET + sizeof(uint16_t)

#define TCP_HEADER_SIZE         (TCP_URG_PTR_OFFSET + sizeof(uint16_t))



/* UDP HEADER OFFSETS */
#define UDP_SRC_PORT_OFFSET     0
#define UDP_DST_PORT_OFFSET     UDP_SRC_PORT_OFFSET + sizeof(uint16_t)
#define UDP_LENGTH_OFFSET       UDP_DST_PORT_OFFSET + sizeof(uint16_t)
#define UDP_CHECKSUM_OFFSET     UDP_LENGTH_OFFSET + sizeof(uint16_t)

#define UDP_HEADER_SIZE         8


/* ICMP HEADER OFFSETS */
#define ICMPV4_TYPE_OFFSET      0
#define ICMPV4_CODE_OFFSET      ICMPV4_TYPE_OFFSET + sizeof(uint8_t)
#define ICMPV4_CHECKSUM_OFFSET  ICMPV4_CODE_OFFSET + sizeof(uint8_t)

#define ICMPV6_TYPE_OFFSET      0
#define ICMPV6_CODE_OFFSET      ICMPV6_TYPE_OFFSET + sizeof(uint8_t)
#define ICMPV6_CHECKSUM_OFFSET  ICMPV6_CODE_OFFSET + sizeof(uint8_t)


#define ICMP_HEADER_SIZE        20
#define ICMP_IP_OFFSET          8
#define ICMP_UDP_OFFSET         ICMP_IP_OFFSET + UDP_HEADER_SIZE




/*  DHCP HEADER OFFSETS */
#define DHCP_OP_OFFSET              0
#define DHCP_HTYPE_OFFSET           DHCP_OP_OFFSET + sizeof(uint8_t)
#define DHCP_HLEN_OFFSET            DHCP_HTYPE_OFFSET + sizeof(uint8_t)
#define DHCP_HOPS_OFFSET            DHCP_HLEN_OFFSET + sizeof(uint8_t)
#define DHCP_XID_OFFSET             DHCP_HOPS_OFFSET + sizeof(uint8_t)
#define DHCP_SECS_OFFSET            DHCP_XID_OFFSET + sizeof(uint32_t)
#define DHCP_FLAGS_OFFSET           DHCP_SECS_OFFSET + sizeof(uint16_t)
#define DHCP_CIADDR_OFFSET          DHCP_FLAGS_OFFSET + sizeof(uint16_t)
#define DHCP_YIADDR_OFFSET          DHCP_CIADDR_OFFSET + sizeof(uint32_t)
#define DHCP_SIADDR_OFFSET          DHCP_YIADDR_OFFSET + sizeof(uint32_t)
#define DHCP_GIADDR_OFFSET          DHCP_SIADDR_OFFSET + sizeof(uint32_t)
#define DHCP_CHADDR_OFFSET          DHCP_GIADDR_OFFSET + sizeof(uint32_t)
#define DHCP_SERVER_HOST_OFFSET     DHCP_CHADDR_OFFSET + 16 * sizeof(uint8_t)
#define DHCP_BOOT_FILE_OFFSET       DHCP_SERVER_HOST_OFFSET + 64 * sizeof(uint8_t)
#define DHCP_MAGIC_OFFSET           DHCP_BOOT_FILE_OFFSET + 128 * sizeof(uint8_t)
#define DHCP_OPTIONS_OFFSET         DHCP_MAGIC_OFFSET + sizeof(uint32_t)



#ifdef __cplusplus
}
#endif

#endif
