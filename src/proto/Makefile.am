AM_CFLAGS = -std=c99 -Wall -W
AM_CPPFLAGS = -I $(top_srcdir)/include -I $(top_srcdir)/src -D_GNU_SOURCE

noinst_LTLIBRARIES = libproto.la

libproto_la_SOURCES = \
	arp.c bittorrent.c cap.c cifs.c dns.c dns_tcp.c \
	eth.c ftp.c fuzzing.c fuzzing.h \
	http.c liner.c liner.h httper.c httper.h \
	icmp.c icmpv6.c ip_hdr.h ip.c ip6.c mgcp.c netbios.c \
	port_muxer.c proto.c \
	rtcp.c rtp.c \
	sdp.c sdper.c sdper.h \
	sip.c ssl.c \
	tcp.c udp.c

libproto_la_LIBADD = ../tools/libtools.la
libproto_la_LDFLAGS = -export-dynamic
