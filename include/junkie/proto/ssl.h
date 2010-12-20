// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef SSL_H_100409
#define SSL_H_100409
#include <junkie/proto/proto.h>

/** @file
 * @brief SSL protocol discovery
 */

extern struct proto *proto_ssl;

struct ssl_proto_info {
    struct proto_info info;
    enum ssl_mode {
        SSL_UNSET, SSL_v2, SSL_v3, SSL_TLS
    } mode;
};

char const *ssl_mode_2_str(enum ssl_mode);

void ssl_init(void);
void ssl_fini(void);

#endif
