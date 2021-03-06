// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>
#include "digest_queue.c"

static void check_hash(uint8_t *raw, size_t size, size_t eth_extra_bytes)
{
    struct frame frame;
    frame.data = raw;
    frame.cap_len = frame.wire_len = size;
    frame.pkt_source = NULL;

    uint8_t hash1[BUFSIZE_TO_HASH] = "";
    uint8_t hash2[BUFSIZE_TO_HASH] = "";

    digest_frame(hash1, &frame);
    size_t iphdr_offset = ETHER_HEADER_SIZE + eth_extra_bytes;

    /* we modify a mac address, the hash shouldn't change */
    frame.data[0] = 0xff;
    digest_frame(hash2, &frame);
    assert(0 == memcmp(hash1, hash2, sizeof hash1));

    /* We change the TOS, the hash shouldn't change */
    frame.data[iphdr_offset + IPV4_TOS_OFFSET] =
        !frame.data[iphdr_offset + IPV4_TOS_OFFSET];
    digest_frame(hash2, &frame);
    assert(0 == memcmp(hash1, hash2, sizeof hash1));

    /* We change the IP Hdr checksum, the hash shouldn't change */
    frame.data[iphdr_offset + IPV4_CHECKSUM_OFFSET] =
        !frame.data[iphdr_offset + IPV4_CHECKSUM_OFFSET];
    digest_frame(hash2, &frame);
    assert(0 == memcmp(hash1, hash2, sizeof hash1));

    /* But if we change another value, the hash MUST change! */
    frame.data[iphdr_offset + IPV4_SRC_HOST_OFFSET] =
        !frame.data[iphdr_offset + IPV4_SRC_HOST_OFFSET];
    digest_frame(hash2, &frame);
    assert(0 != memcmp(hash1, hash2, sizeof hash1));
}

static void test_digest_frame_standard(void)
{
    // Frame without linux cooked capture activated (ethertype = 0x0000)
    uint8_t raw[BUFSIZE_TO_HASH] = {
        // ethernet header
        0x00, 0x03, 0x00, 0x01, 0x00, 0x06, 0x00, 0x50,
        0x56, 0xb8, 0x43, 0xfd,
        0x08, 0x00, // ipv4

        // ip header
        0x45, 0x00, 0x00, 0x29, 0x1c, 0xf1, 0x40, 0x00,
        0x80, 0x06, 0xba, 0x84, 0xc0, 0xa8, 0xb5, 0x05,
        0xac, 0x11, 0x01, 0x9a,

        // tcp header
        0x01, 0xbd, 0x3e, 0x4f, 0x21, 0xff, 0x03, 0xd9,
        0x4e, 0x0d, 0xe0, 0x8c, 0x50, 0x10, 0xf5, 0x85,
        0x02, 0x76, 0x00, 0x00,

        // payload
        0x00, 0x00,
    };

    check_hash(raw, sizeof raw, 0);
}

static void test_digest_frame_vlanid(void)
{
    // Frame without linux cooked capture activated (ethertype = 0x0000)
    uint8_t raw[BUFSIZE_TO_HASH] = {
        // ethernet header
        0x00, 0x03, 0x00, 0x01, 0x00, 0x06, // dst mac
        0x00, 0x50, 0x56, 0xb8, 0x43, 0xfd, // src mac
        0x81, 0x00, // vlan
        0xab, 0xcd, 0x12, 0x34, // id

        // ip header
        0x45, 0x00, 0x00, 0x29, 0x1c, 0xf1, 0x40, 0x00,
        0x80, 0x06, 0xba, 0x84, 0xc0, 0xa8, 0xb5, 0x05,
        0xac, 0x11, 0x01, 0x9a,

        // tcp header
        0x01, 0xbd, 0x3e, 0x4f, 0x21, 0xff, 0x03, 0xd9,
        0x4e, 0x0d, 0xe0, 0x8c, 0x50, 0x10, 0xf5, 0x85,
        0x02, 0x76, 0x00, 0x00,

        // payload
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    check_hash(raw, sizeof raw, 4);
}

static void test_digest_frame_lcc(void)
{
    // Frame with linux cooked capture activated (ethertype = 0x0000)
    uint8_t raw[BUFSIZE_TO_HASH] = {
        // ethernet header
        0x00, 0x03, 0x00, 0x01, 0x00, 0x06, 0x00, 0x50,
        0x56, 0xb8, 0x43, 0xfd,
        0x00, 0x00, // lcc
        0x08, 0x00, // ipv4

        // ip header
        0x45, 0x00, 0x00, 0x29, 0x1c, 0xf1, 0x40, 0x00,
        0x80, 0x06, 0xba, 0x84, 0xc0, 0xa8, 0xb5, 0x05,
        0xac, 0x11, 0x01, 0x9a,

        // tcp header
        0x01, 0xbd, 0x3e, 0x4f, 0x21, 0xff, 0x03, 0xd9,
        0x4e, 0x0d, 0xe0, 0x8c, 0x50, 0x10, 0xf5, 0x85,
        0x02, 0x76, 0x00, 0x00,

        // payload
        0x00, 0x00,
    };

    check_hash(raw, sizeof raw, 2);
}

static void test_digest_frame_lcc_and_vlanid(void)
{
    // Frame without linux cooked capture activated (ethertype = 0x0000)
    uint8_t raw[BUFSIZE_TO_HASH] = {
        // ethernet header
        0x00, 0x03, 0x00, 0x01, 0x00, 0x06, // dst mac
        0x00, 0x50, 0x56, 0xb8, 0x43, 0xfd, // src mac
        0x00, 0x00, // lcc
        0x81, 0x00, // vlan
        0xab, 0xcd, 0x12, 0x34, // vlanid

        // ip header
        0x45, 0x00, 0x00, 0x29, 0x1c, 0xf1, 0x40, 0x00,
        0x80, 0x06, 0xba, 0x84, 0xc0, 0xa8, 0xb5, 0x05,
        0xac, 0x11, 0x01, 0x9a,

        // tcp header
        0x01, 0xbd, 0x3e, 0x4f, 0x21, 0xff, 0x03, 0xd9,
        0x4e, 0x0d, 0xe0, 0x8c, 0x50, 0x10, 0xf5, 0x85,
        0x02, 0x76, 0x00, 0x00,

        // payload
        0x00, 0x00,
    };

    check_hash(raw, sizeof raw, 6);
}

int main(void)
{
    log_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("digest_queue_check.log");

    test_digest_frame_standard();
    test_digest_frame_vlanid();

    test_digest_frame_lcc();
    test_digest_frame_lcc_and_vlanid();

    log_fini();
    return EXIT_SUCCESS;
}

