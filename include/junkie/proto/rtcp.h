// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef RTCP_H_101221
#define RTCP_H_101221
#include <junkie/proto/proto.h>

/** @file
 * @brief RTCP informations
 */

extern struct proto *proto_rtcp;

struct rtcp_proto_info {
    struct proto_info info;

    int32_t cumul_lost; ///< Cumulative number of packets lost
    uint32_t jitter;    ///< Interarrival Jitter
    uint32_t lsr;       ///< Last SR timestamp
    uint32_t dlsr;      ///< Delay since Last SR timestamp
    uint32_t ntp_ts;    ///< NTP timestamp
};

void rtcp_init(void);
void rtcp_fini(void);

#endif
