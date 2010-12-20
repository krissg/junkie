// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SDP_H
#define SDP_H
#include <junkie/proto/proto.h>
#include <junkie/tools/ip_addr.h>

/** @file
 * @brief SDP informations
 */

extern struct proto *proto_sdp;

struct sdp_proto_info {
  struct proto_info info;

#define SDP_HOST_SET 0x1
#define SDP_PORT_SET 0x2
  uint32_t set_values;

  struct ip_addr host;
  uint16_t port;
};

void sdp_init(void);
void sdp_fini(void);

#endif
