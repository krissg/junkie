// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#ifndef DIGEST_QUEUE_H
#define DIGEST_QUEUE_H

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

#include "pkt_source.h"


#define DIGEST_BUFSIZE 100
#define DIGEST_SIZE 16

struct digest_qcell
{
    uint8_t digest[DIGEST_SIZE];
    struct timeval tv;
};


struct digest_queue
{
    struct digest_qcell *digests;
    uint32_t             idx;
    size_t               size;
};


void digest_queue_ctor(struct digest_queue *q, size_t size);

void digest_queue_dtor(struct digest_queue *q);

void digest_queue_push(struct digest_queue* q, uint8_t digest[DIGEST_SIZE],
                       const struct frame *frm);

void digest_frame(uint8_t *buf, struct frame *frm);


#ifdef __cplusplus
}
#endif

#endif /* DIGEST_QUEUE_H */
