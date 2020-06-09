# Automake file for FILL_PROGRAM_NAME

sharedatadir = $(pkgdatadir)/data

bin_PROGRAMS = miniospf6
miniospf6_SOURCES = miniospf6.c common6.h \
	lsa6.c lsa6.h \
	ospf6.c ospf6.h \
	ospf-changes6.c ospf-changes6.h \
	sockopt6.c sockopt6.h


miniospf6_CPPFLAGS = -DSHAREDATA_DIR=\"$(sharedatadir)/\" -DLOCALEDIR=\"$(localedir)\" $(AM_CPPFLAGS) -I$(srcdir)/../lib
miniospf6_CFLAGS = $(LIBNL_CFLAGS) $(AM_CFLAGS)
miniospf6_LDADD = $(LIBNL_LIBS) ../lib/libminiospf.a
LDADD = $(LIBINTL)

