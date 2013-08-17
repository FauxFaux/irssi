moduledir = $(libdir)/irssi/modules
module_LTLIBRARIES = libirc_irssicp.la

INCLUDES = \
	-I$(top_srcdir)/src \
	-I$(top_srcdir)/src/core/ \
	-I$(top_srcdir)/src/irc/core/ \
	-I$(top_srcdir)/src/fe-common/core/ \
	$(GLIB_CFLAGS)

libirc_irssicp.a:
	rm -f libirc_irssicp.a
	$(LN_S) .libs/libirc_irssicp.a libirc_irssicp.a

libirc_irssicp_la_LDFLAGS = -module -avoid-version

libirc_irssicp_la_DEPENDENCIES = libirc_irssicp.a

libirc_irssicp_la_SOURCES = \
	irssicp.c

noinst_HEADERS =

clean-generic:
	rm -f libirc_irssicp.a
