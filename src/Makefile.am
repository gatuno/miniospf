# Automake file for FILL_PROGRAM_NAME

sharedatadir = $(pkgdatadir)/data

bin_PROGRAMS = miniospf
miniospf_SOURCES = miniospf.c common.h \
	glist.c glist.h \
	interfaces.c interfaces.h \
	ip-address.c ip-address.h \
	netlink-events.c netlink-events.h \
	utils.c utils.h \
	lsa.c lsa.h \
	ospf.c ospf.h \
	ospf-changes.c ospf-changes.h \
	sockopt.c sockopt.h


miniospf_CPPFLAGS = -DSHAREDATA_DIR=\"$(sharedatadir)/\" -DLOCALEDIR=\"$(localedir)\" $(AM_CPPFLAGS)
miniospf_CFLAGS = $(LIBNL_CFLAGS) $(AM_CFLAGS)
miniospf_LDADD = $(LIBNL_LIBS) -lm
LDADD = $(LIBINTL)

