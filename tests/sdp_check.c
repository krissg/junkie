// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
#include <stdlib.h>
#include <assert.h>
#include <time.h>
#include <junkie/cpp.h>
#include <junkie/proto/ip.h>
#include "lib.h"
#include "proto/sdp.c"

/*
 * Parse check
 */

static struct parse_test {
    uint8_t const packet[200];
    uint16_t port;
    char *ip;
    enum proto_parse_status ret;
} parse_tests[] = {

    {
        .packet =
        "c=IN IP4 192.168.129.14\r\n"
        "m=audio 8000 RTP/AVP 98 97 8 0 3 101\r\n"
        "\r\n",
        .port = 8000,
        .ip = "192.168.129.14",
        .ret = PROTO_OK,
    },

    {
        .packet =
        "c=IN IP 1.2.3.4\r\n" // missing IP version
        "m=audio 8000\r\n",
        .port = 8000,
        .ip = "0.0.0.0",
        .ret = PROTO_PARSE_ERR,
    },

    {
        .packet =
        "c=IN IP4 1.2.3.4\r\n"
        "m=8000\r\n", // missing format (e.g. "audio", ...)
        .port = 0,
        .ip = "1.2.3.4",
        .ret = PROTO_PARSE_ERR,
    },

    {
        .packet =
        "c=IN IP5 192.168.129.14\r\n" // ipv5 not supported
        "m=video 8000 RTP/AVP 98 97 8 0 3 101\r\n" // video instead of audio is OK
        "\r\n",
        .port = 8000,
        .ip = "0.0.0.0",
        .ret = PROTO_PARSE_ERR,
    },

};

static unsigned cur_test;

static int sdp_info_check(struct proto_layer *layer)
{
    // Check layer->info against parse_tests[cur_test].expected
    struct sdp_proto_info const *const info = DOWNCAST(layer->info, info, sdp_proto_info);
    uint16_t port = parse_tests[cur_test].port;
    char    *ip   = parse_tests[cur_test].ip;

    // TODO: fix these checks
/*     assert(info->info.head_len == expected->info.head_len); */
/*     assert(info->info.payload == expected->info.payload); */
    assert(info->port == port);

    struct ip_addr exp_addr;
    (void)ip_addr_ctor_from_str(&exp_addr, ip, strlen(ip), 4);
    assert(0 == ip_addr_cmp(&info->host, &exp_addr));

    return 0;
}

static void parse_check(void)
{
    struct timeval now;
    timeval_set_now(&now);
    struct parser *sdp_parser = proto_sdp->ops->parser_new(proto_sdp, &now);
    assert(sdp_parser);

    for (cur_test = 0; cur_test < NB_ELEMS(parse_tests); cur_test++) {
        size_t const len = strlen((char *)parse_tests[cur_test].packet);
        enum proto_parse_status ret = sdp_parse(sdp_parser, NULL, 0, parse_tests[cur_test].packet, len, len, &now, sdp_info_check);
        assert(parse_tests[cur_test].ret == ret);
    }

    parser_unref(sdp_parser);
}

int main(void)
{
    log_init();
    sdp_init();
    log_set_level(LOG_DEBUG, NULL);
    log_set_file("sdp_check.log");

    parse_check();
    stress_check(proto_sdp);

    sdp_fini();
    log_fini();
    return EXIT_SUCCESS;
}

