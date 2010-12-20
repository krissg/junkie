// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef FTP_H_100414
#include <junkie/proto/proto.h>

/** @file
 * @brief FTP informations
 */

extern struct proto *proto_ftp;

/// FTP message (not much information here)
struct ftp_proto_info {
    struct proto_info info;
    // and...?
};

void ftp_init(void);
void ftp_fini(void);

#endif
