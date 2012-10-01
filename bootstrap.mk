
MANUAL_FILES = NEWS README AUTHORS ChangeLog

MAKE_AM = Makefile.am src/Makefile.am c_src/Makefile.am
MAKE_IN = Makefile.in src/Makefile.in c_src/Makefile.in

ALL_TARGET = $(MANUAL_FILES) config.h.in configure $(MAKE_IN)

CLEAN_FILES = config.h.in

default: $(ALL_TARGET)

CLEAN_FILES += NEWS ChangeLog

$(MANUAL_FILES):
	touch $@

manual: $(MANUAL_FILES)

CONFIG_DIR = config
CLEAN_FILES += $(CONFIG_DIR)

$(CONFIG_DIR)/ltmain.sh:
	mkdir $(CONFIG_DIR)
	libtoolize

$(MAKE_IN): $(MAKE_AM) $(wildcard configure.ac configure.in) $(CONFIG_DIR)/ltmain.sh
	automake --gnu --add-missing --copy

CLEAN_FILES += INSTALL COPYING $(MAKE_IN)

config.h.in: $(wildcard configure.ac configure.in)
	autoheader

configure: $(wildcard configure.ac configure.in) aclocal.m4
	autoconf -i

aclocal.m4: $(wildcard configure.ac configure.in)
	aclocal

CLEAN_FILES += configure
CLEAN_FILES += aclocal.m4 autom4te.cache

# files created by configure
CLEAN_FILES += config.h config.log config.status .deps libtool Makefile stamp-h1 src/Makefile c_src/Makefile c_src/.deps

CLEAN_FILES += config.h.in~

clean:
	rm -fr $(CLEAN_FILES)
