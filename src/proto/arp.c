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
#include <string.h>
#include <stdbool.h>
#include <junkie/cpp.h>
#include <junkie/tools/log.h>
#include <junkie/tools/ip_addr.h>
#include <junkie/proto/proto.h>
#include <junkie/proto/arp.h>

static char const Id[] = "$Id: 41d9ce8a5da8afbfb5153b5c45632295bc52b6f9 $";

#undef LOG_CAT
#define LOG_CAT proto_arp_log_category

LOG_CATEGORY_DEC(proto_arp);
LOG_CATEGORY_DEF(proto_arp);

/*
 * Parse
 */

static enum proto_parse_status arp_parse(struct parser unused_ *parser, struct proto_layer unused_ *parent, unsigned unused_ way, uint8_t const unused_ *packet, size_t unused_ cap_len, size_t unused_ wire_len, struct timeval unused_ const *now, proto_okfn_t unused_ *okfn)
{
	// TODO
	return PROTO_PARSE_ERR;
}

/*
 * Construction/Destruction
 */

static struct uniq_proto uniq_proto_arp;
struct proto *proto_arp = &uniq_proto_arp.proto;

void arp_init(void)
{
    log_category_proto_arp_init();

	static struct proto_ops const ops = {
		.parse = arp_parse,
		.parser_new = uniq_parser_new,
		.parser_del = uniq_parser_del,
	};
	uniq_proto_ctor(&uniq_proto_arp, &ops, "ARP");
}

void arp_fini(void)
{
	uniq_proto_dtor(&uniq_proto_arp);
    log_category_proto_arp_fini();
}
