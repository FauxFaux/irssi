moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_bitserv.la

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	$(GLIB_CFLAGS)

libirc_bitserv.a:
	rm -f libirc_bitserv.a
	$(LN_S) .libs/libirc_bitserv.a libirc_bitserv.a

libirc_bitserv_la_LDFLAGS = -module -avoid-version

libirc_bitserv_la_DEPENDENCIES = libirc_bitserv.a

libirc_bitserv_la_SOURCES = \
	bitserv.c \
	dump.c \
	listen.c

noinst_HEADERS = \
	module.h \
	bitserv.h

clean-generic:
	rm -f libirc_bitserv.a
