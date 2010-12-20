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

# When absent (when fetching from guile and running autogen.sh), version.conf is generated from git infos
version.conf:
	@echo "TAGNAME = \"$(shell git describe --tags)\"" > $@
	@echo "BRANCHNAME = \"$(shell git symbolic-ref HEAD | cut -d/ -f 3-)\"" >> $@
	@echo "COMP_HOST = \"$(shell hostname)\"" >> $@

# But once created, it is saved in the dist file so building from dist is possible
EXTRA_DIST = version.conf
