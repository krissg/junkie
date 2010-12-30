#ifndef IP_HDR_H_101230
#define IP_HDR_H_101230
#include <stdint.h>
#include <junkie/config.h>
#include <junkie/cpp.h>
#include <netinet/in.h>	// For struct in6_addr (same than in ip_addr.h)

// Definition of an IP header
struct ip_hdr {
#   ifdef WORDS_BIGENDIAN
    uint8_t version:4;
    uint8_t hdr_len:4;
#   else
    uint8_t hdr_len:4;
    uint8_t version:4;
#   endif
    uint8_t tos;
    uint16_t tot_len;
    uint16_t id;
    uint16_t fragment_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint32_t src;
    uint32_t dst;
    // Then options
} packed_;

// Definition of an IPv6 header
struct ipv6_hdr {
#   ifdef WORDS_BIGENDIAN
    uint32_t version:4;
    uint32_t class:4;
    uint32_t flow:24;
#   else
    uint32_t flow:24;
    uint32_t class:4;
    uint32_t version:4;
#   endif
    uint16_t payload_len;
    uint8_t next;
    uint8_t hop_limit;
    struct in6_addr src;
    struct in6_addr dst;
} packed_;

// Definition of an ICMP header
struct icmp_hdr {
  uint8_t type;
  uint8_t code;
  uint16_t checksum;
  uint32_t compl;
} packed_;

// Definition of an UDP header
struct udp_hdr
{
  uint16_t src;
  uint16_t dst;
  uint16_t len;
  uint16_t checksum;
} packed_;

// Definition of a TCP header
struct tcp_hdr {
    uint16_t src;
    uint16_t dst;
    uint32_t seq_num;
    uint32_t ack_seq;
#   ifdef WORDS_BIGENDIAN
    uint16_t doff:4;
    uint16_t res1:4;
    uint16_t res2:2;
    uint16_t urg:1;
    uint16_t ack:1;
    uint16_t psh:1;
    uint16_t rst:1;
    uint16_t syn:1;
    uint16_t fin:1;
#   else
    uint16_t res1:4;
    uint16_t doff:4;
    uint16_t fin:1;
    uint16_t syn:1;
    uint16_t rst:1;
    uint16_t psh:1;
    uint16_t ack:1;
    uint16_t urg:1;
    uint16_t res2:2;
#   endif
    uint16_t window;
    uint16_t checksum;
    uint16_t urg_ptr;
} packed_;

#endif
