SUBDIRS = src c_src

# Erlang documentation generator
edoc:
	cd src && $(MAKE) $(AM_MAKEFLAGS) $@

DISTCLEANFILES = config.h.in config.h.in~ configure aclocal.m4 NEWS ChangeLog \
			   Makefile.in src/Makefile.in c_src/Makefile.in
distclean-local:
	-rm -fr m4 autom4te.cache config install
