// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef BITTORRENT_H_100409
#define BITTORRENT_H_100409
#include <junkie/proto/proto.h>

/** @file
 * @brief Bittorrent protocol discovery.
 */

extern struct proto *proto_bittorrent;

struct bittorrent_proto_info {
    struct proto_info info;
};

void bittorrent_init(void);
void bittorrent_fini(void);

#endif
