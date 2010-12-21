AUTOMAKE_OPTIONS = foreign
ACLOCAL_AMFLAGS = -I m4

dist_doc_DATA = README COPYING LICENSE.AGPL LICENSE.BSD LICENSE.LGPL LICENSE.OpenSSL KNOWN_ISSUES USAGE

SUBDIRS = include src config plugins/dumper tests

.PHONY: cscope doc

cscope:
	cd $(top_srcdir) && cscope -Rb $(CPPFLAGS)

distclean-local:
	rm -f cscope.out

doc: Doxyfile
	doxygen $<
