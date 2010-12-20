// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef HTTPER_H_100505
#define HTTPER_H_100505
#include <stdint.h>
#include "proto/liner.h"

struct httper {
    // For first command line
    unsigned nb_commands;
    struct httper_command {
        char const *name;
        size_t len;
        int (*cb)(unsigned cmd, struct liner *, void *);
    } const *commands;
    // For header fields
    unsigned nb_fields;
    struct httper_field {
        char const *name;
        size_t len;
        int (*cb)(unsigned field, struct liner *, void *);
    } const *fields;
};

/// @returns -1 if none of the given command was found
/// @note If you have several commands that share a common prefix you must order them longest first
int httper_parse(struct httper const *, size_t *head_sz, uint8_t const *packet, size_t packet_len, void *);

#endif
