// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include "lib.h"
#include "proto/arp.c"

/*
 * Parse check
 */

static struct parse_test {
    uint8_t const packet[46];
    size_t cap_len, wire_len;
    enum proto_parse_status status;
    struct expected {
        size_t head_len, payload;
        unsigned opcode;
        bool proto_addr_is_ip, hw_addr_is_eth;
        char const *ip_sender, *ip_target, *hw_target;
    } expected;
} parse_tests[] = {
    {
        .packet = { 0x0 },
        .cap_len = 0,
        .wire_len = 0,
        .status = PROTO_PARSE_ERR,
        .expected = { 0, 0, 0, 0, 0, 0, 0, 0, },
    }, {
        .packet = {
            0x00U, 0x01U, 0x08U, 0x00U, 0x06U, 0x04U, 0x00U, 0x01U,
            0x00U, 0x1bU, 0x17U, 0x0aU, 0x4eU, 0x11U, 0xc0U, 0xa8U,
            0x14U, 0x39U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
        },
        .cap_len = 24, .wire_len = 46,
        .status = PROTO_TOO_SHORT,
        .expected = { 0, 0, 0, 0, 0, 0, 0, 0, },
    }, {
        .packet = {
            0x00U, 0x01U, 0x08U, 0x00U, 0x06U, 0x04U, 0x00U, 0x01U,
            0x00U, 0x1bU, 0x17U, 0x0aU, 0x4eU, 0x11U, 0xc0U, 0xa8U,
            0x14U, 0x39U, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU, 0xffU,
            0xc0U, 0xa8U, 0x14U, 0xffU, 0x00U, 0x00U, 0x00U, 0x00U,
        },
        .cap_len = 46, .wire_len = 32,
        .status = PROTO_OK,
        .expected = {
            .head_len = 28, // actual size of ARP
            .payload = 4,   // the "payload" here are just padding bytes
            .opcode = 1,
            .proto_addr_is_ip = true,
            .hw_addr_is_eth = true,
            .ip_sender = "192.168.20.57",
            .ip_target = "192.168.20.255",
            .hw_target = "ff:ff:ff:ff:ff:ff",
        },
    },
};

static unsigned cur_test;

static int arp_info_check(struct proto_layer *layer)
{
    struct arp_proto_info const *const info = DOWNCAST(layer->info, info, arp_proto_info);
    struct expected const *const exp = &parse_tests[cur_test].expected;

    assert(info->info.head_len == exp->head_len);
    assert(info->info.payload == exp->payload);
    assert(info->opcode == exp->opcode);
    assert(info->proto_addr_is_ip == exp->proto_addr_is_ip);
    assert(info->hw_addr_is_eth == exp->hw_addr_is_eth);
    if (info->proto_addr_is_ip) {
        assert(0 == strcasecmp(ip_addr_2_str(&info->sender), exp->ip_sender));
        assert(0 == strcasecmp(ip_addr_2_str(&info->target), exp->ip_target));
    }
    if (info->hw_addr_is_eth) {
        assert(0 == strcasecmp(eth_addr_2_str(info->hw_target), exp->hw_target));
    }

    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *arp_parser = proto_arp->ops->parser_new(proto_arp, &now);
    assert(arp_parser);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        struct parse_test const *const test = parse_tests + cur_test;
        enum proto_parse_status status = arp_parse(arp_parser, NULL, 0, test->packet, test->cap_len, test->wire_len, &now, arp_info_check);
        assert(status == test->status);
    }

    parser_unref(arp_parser);
}

int main(void)
{
    log_init();
    eth_init();
    arp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("arp_check.log");

    parse_check();
    stress_check(proto_arp);

    arp_fini();
    eth_fini();
    log_fini();
    return EXIT_SUCCESS;
}
