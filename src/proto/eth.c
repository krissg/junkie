// -*- c-basic-offset: 4; c-backslash-column: 79; indent-tabs-mode: nil -*-
// vim:sw=4 ts=4 sts=4 expandtab
/* Copyright 2010, SecurActive.
 *
 * This file is part of Junkie.
 *
 * Junkie is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Junkie is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with Junkie.  If not, see <http://www.gnu.org/licenses/>.
 */
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>
#include <inttypes.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/tempstr.h>
#include <junkie/tools/miscmacs.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/ip.h>
#include <junkie/proto/arp.h>
#include <junkie/proto/eth.h>
#include <junkie/ext.h>

static char const Id[] = "$Id: 70c2033b6d5c020b1a0f8c367cf57c2cfb996c84 $";

#undef LOG_CAT
#define LOG_CAT proto_eth_log_category

LOG_CATEGORY_DEC(proto_eth);
LOG_CATEGORY_DEF(proto_eth);

#define ETH_TIMEOUT (60*60)

static bool collapse_vlans = true;
EXT_PARAM_RW(collapse_vlans, "collapse-vlans", bool, "Set to true if packets from distinct vlans share the same address range");
static const uint16_t zero = 0;

// Description of an Ethernet header
struct eth_hdr {
	unsigned char dst[ETH_ADDR_LEN];
	unsigned char src[ETH_ADDR_LEN];
	uint16_t proto;
} packed_;

/*
 * Proto Infos
 */

char const *eth_addr_2_str(unsigned char const addr[ETH_ADDR_LEN])
{
    char *str = tempstr();
    size_t len = 0;
    unsigned i;
    for (i = 0; i < ETH_ADDR_LEN; i ++) {
        len += snprintf(str+len, TEMPSTR_SIZE-len, "%s%.02x", len > 0 ? ":":"", addr[i]);
    }
    return str;
}

static char const *eth_info_2_str(struct proto_info const *info_)
{
    struct eth_proto_info const *info = DOWNCAST(info_, info, eth_proto_info);
    char *str = tempstr();
    snprintf(str, TEMPSTR_SIZE, "%s, vlan_id=%"PRIu16", source=%s, dest=%s, proto=%u",
        proto_info_2_str(info_),
        info->vlan_id,
        eth_addr_2_str(info->addr[0]),
        eth_addr_2_str(info->addr[1]),
        info->protocol);
    return str;
}

static void eth_proto_info_ctor(struct eth_proto_info *info, size_t head_len, size_t payload, uint16_t proto, uint16_t vlan_id, struct eth_hdr const *ethhdr)
{
    static struct proto_info_ops ops = {
        .to_str = eth_info_2_str,
    };
    proto_info_ctor(&info->info, &ops, head_len, payload);

    info->vlan_id = collapse_vlans ? zero : vlan_id;
    ASSERT_COMPILE(sizeof(info->addr[0]) == sizeof(ethhdr->src));
    memcpy(info->addr[0], ethhdr->src, sizeof(info->addr[0]));
    ASSERT_COMPILE(sizeof(info->addr[1]) == sizeof(ethhdr->dst));
    memcpy(info->addr[1], ethhdr->dst, sizeof(info->addr[1]));
    info->protocol = proto;
}

/*
 * Subproto management
 */

static LIST_HEAD(eth_subprotos, eth_subproto) eth_subprotos;

void eth_subproto_ctor(struct eth_subproto *eth_subproto, unsigned protocol, struct proto *proto)
{
    SLOG(LOG_DEBUG, "Adding proto %s for protocol value %u", proto->name, protocol);
    eth_subproto->protocol = protocol;
    eth_subproto->proto = proto;
    LIST_INSERT_HEAD(&eth_subprotos, eth_subproto, entry);
}

void eth_subproto_dtor(struct eth_subproto *eth_subproto)
{
    SLOG(LOG_DEBUG, "Removing proto %s for protocol value %u", eth_subproto->proto->name, eth_subproto->protocol);
    LIST_REMOVE(eth_subproto, entry);
}

/*
 * Parse
 */

struct mux_subparser *eth_subparser_and_parser_new(struct parser *parser, struct proto *proto, struct parser *requestor, uint16_t vlan_id, struct timeval const *now)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    return mux_subparser_and_parser_new(mux_parser, proto, requestor, collapse_vlans ? &zero : &vlan_id, now);
}

static enum proto_parse_status eth_parse(struct parser *parser, struct proto_layer *parent, unsigned way, uint8_t const *packet, size_t cap_len, size_t wire_len, struct timeval const *now, proto_okfn_t *okfn)
{
    struct mux_parser *mux_parser = DOWNCAST(parser, parser, mux_parser);
    struct eth_hdr const *ethhdr = (struct eth_hdr *)packet;
    uint16_t h_proto = ntohs(ethhdr->proto);
    uint16_t vlan_id = 0;
    size_t ethhdr_len = sizeof(*ethhdr);

    // Sanity checks
    if (wire_len < ethhdr_len) {
        SLOG(LOG_DEBUG, "Bogus Eth packet: too short (%zu < %zu)", wire_len, ethhdr_len);
        return PROTO_PARSE_ERR;
    }

    if (cap_len < ethhdr_len) return PROTO_TOO_SHORT;

    if (h_proto == 0) {  // Take into account Linux Cooked Capture
        if (cap_len < ethhdr_len + 2) return PROTO_TOO_SHORT;
        struct eth_lcc {
            uint16_t h_proto;
        } packed_ *eth_lcc = (struct eth_lcc *)((char *)ethhdr + ethhdr_len);
        h_proto = ntohs(eth_lcc->h_proto);
        ethhdr_len += 2;
        // We dont care about the source MAC being funny
    }

    if (h_proto == ETH_PROTO_8021Q) {   // Take into account 802.1q vlan tag
        if (cap_len < ethhdr_len + 4) return PROTO_TOO_SHORT;
        struct eth_vlan {
            uint16_t vlan_id, h_proto;
        } packed_ *eth_vlan = (struct eth_vlan *)((char *)ethhdr + ethhdr_len);
        h_proto = ntohs(eth_vlan->h_proto);
        vlan_id = ntohs(eth_vlan->vlan_id) & 0xfff;
        ethhdr_len += 4;
    }

    // Parse
    struct eth_proto_info info;
    eth_proto_info_ctor(&info, ethhdr_len, wire_len - ethhdr_len, h_proto, vlan_id, ethhdr);
    struct proto_layer layer;
    proto_layer_ctor(&layer, parent, parser, &info.info);

    struct proto *sub_proto = NULL;
    struct eth_subproto *subproto;
    LIST_FOREACH(subproto, &eth_subprotos, entry) {
        if (subproto->protocol == h_proto) {
            sub_proto = subproto->proto;
            break;
        }
    }
    struct mux_subparser *subparser = mux_subparser_lookup(mux_parser, sub_proto, NULL, collapse_vlans ? &zero : &vlan_id, now);

    if (! subparser) goto fallback;

    assert(ethhdr_len <= cap_len);
    if (0 != proto_parse(subparser->parser, &layer, way, packet + ethhdr_len, cap_len - ethhdr_len, wire_len - ethhdr_len, now, okfn)) goto fallback;
    return PROTO_OK;

fallback:
    (void)proto_parse(NULL, &layer, way, packet + ethhdr_len, cap_len - ethhdr_len, wire_len - ethhdr_len, now, okfn);
    return PROTO_OK;
}

/*
 * Construction/Destruction
 */

static struct mux_proto mux_proto_eth;
struct proto *proto_eth = &mux_proto_eth.proto;

void eth_init(void)
{
    log_category_proto_eth_init();
    ext_param_collapse_vlans_init();

    static struct proto_ops const ops = {
        .parse = eth_parse,
        .parser_new = mux_parser_new,
        .parser_del = mux_parser_del,
    };
    mux_proto_ctor(&mux_proto_eth, &ops, &mux_proto_ops, "Ethernet", ETH_TIMEOUT, sizeof(zero) /* vlan_id */, 8);
    LIST_INIT(&eth_subprotos);
}

void eth_fini(void)
{
    assert(LIST_EMPTY(&eth_subprotos));
    mux_proto_dtor(&mux_proto_eth);
    ext_param_collapse_vlans_fini();
    log_category_proto_eth_fini();
}
