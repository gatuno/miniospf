# Automake file for FILL_PROGRAM_NAME

sharedatadir = $(pkgdatadir)/data

bin_PROGRAMS = miniospf
miniospf_SOURCES = miniospf.c common.h \
	lsa.c lsa.h \
	ospf.c ospf.h \
	ospf-changes.c ospf-changes.h \
	sockopt.c sockopt.h


miniospf_CPPFLAGS = -DSHAREDATA_DIR=\"$(sharedatadir)/\" -DLOCALEDIR=\"$(localedir)\" $(AM_CPPFLAGS) -I$(srcdir)/../lib
miniospf_CFLAGS = $(LIBNL_CFLAGS) $(AM_CFLAGS)
miniospf_LDADD = $(LIBNL_LIBS) ../lib/libminiospf.a
LDADD = $(LIBINTL)

