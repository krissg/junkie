##AUTOMAKE_OPTIONS = color-tests
AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src -I $(top_srcdir)/src/proto -D_GNU_SOURCE -DSRCDIR=$(top_srcdir)/tests

check_PROGRAMS = \
	digest_queue_check timeval_check files_check \
	hash_check liner_check ip_addr_check jhash_check \
	log_check redim_array_check mallocer_check \
	ip_check udp_check tcp_check http_check sip_check \
	sdp_check mgcp_check dns_check cnxtrack_check \
	icmp_check rtcp_check flood_check port_range_check \
	arp_check

TESTS = $(check_PROGRAMS)

TESTS_ENVIRONMENT = EF_ALLOW_MALLOC_0=1

#LDFLAGS += -lefence

digest_queue_check_SOURCES = digest_queue_check.c ../src/ext.c
digest_queue_check_LDADD = ../src/tools/libtools.la
timeval_check_SOURCES = timeval_check.c ../src/ext.c
timeval_check_LDADD = ../src/tools/libtools.la
files_check_SOURCES = files_check.c ../src/ext.c
files_check_LDADD = ../src/tools/libtools.la
hash_check_SOURCES = hash_check.c ../src/ext.c
hash_check_LDADD = ../src/tools/libtools.la
liner_check_SOURCES = liner_check.c ../src/ext.c
liner_check_LDADD = ../src/tools/libtools.la
ip_addr_check_SOURCES = ip_addr_check.c ../src/ext.c
ip_addr_check_LDADD = ../src/tools/libtools.la
jhash_check_SOURCES = jhash_check.c
log_check_SOURCES = log_check.c ../src/ext.c
log_check_LDADD = ../src/tools/libtools.la
redim_array_check_SOURCES = redim_array_check.c ../src/ext.c
redim_array_check_LDADD = ../src/tools/libtools.la
mallocer_check_SOURCES = mallocer_check.c ../src/ext.c
mallocer_check_LDADD = ../src/tools/libtools.la

ip_check_SOURCES = ip_check.c lib.c lib.h ../src/ext.c
ip_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
udp_check_SOURCES = udp_check.c lib.c lib.h ../src/ext.c
udp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
tcp_check_SOURCES = tcp_check.c lib.c lib.h ../src/ext.c
tcp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
http_check_SOURCES = http_check.c lib.c lib.h ../src/ext.c
http_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
sip_check_SOURCES = sip_check.c lib.c lib.h ../src/ext.c
sip_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
sdp_check_SOURCES = sdp_check.c lib.c lib.h ../src/ext.c
sdp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
mgcp_check_SOURCES = mgcp_check.c lib.c lib.h ../src/ext.c
mgcp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
dns_check_SOURCES = dns_check.c lib.c lib.h ../src/ext.c
dns_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
cnxtrack_check_SOURCES = cnxtrack_check.c lib.c lib.h ../src/ext.c
cnxtrack_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
icmp_check_SOURCES = icmp_check.c lib.c lib.h ../src/ext.c
icmp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
rtcp_check_SOURCES = rtcp_check.c lib.c lib.h ../src/ext.c
rtcp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
arp_check_SOURCES = arp_check.c lib.c lib.h ../src/ext.c
arp_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
flood_check_SOURCES = flood_check.c lib.c lib.h ../src/ext.c
flood_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la
port_range_check_SOURCES = port_range_check.c lib.c lib.h ../src/ext.c
port_range_check_LDADD = ../src/tools/libtools.la ../src/proto/libproto.la

distclean-local:
	rm -f *.log vgcore.* core.* core

EXTRA_DIST = foreach.txt

