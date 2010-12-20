// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef ARP_H_100402
#define ARP_H_100402
#include <stdint.h>
#include <netinet/ether.h>
#include <junkie/proto/proto.h>

/** @file
 * @brief ARP informations
 */

extern struct proto *proto_arp;

/// Description of an ARP message
struct arp_proto_info {
    struct proto_info info; ///< Generic infos
    uint16_t operation;
    uint8_t sha[ETH_ALEN];
};

void arp_init(void);
void arp_fini(void);

#endif
