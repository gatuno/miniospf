
noinst_LIBRARIES = libminiospf.a
libminiospf_a_SOURCES = glist.c glist.h \
	interfaces.c interfaces.h \
	ip-address.c ip-address.h \
	netlink-events.c netlink-events.h \
	utils.c utils.h \
	netwatcher.h

libminiospf_a_CPPFLAGS = -DSHAREDATA_DIR=\"$(sharedatadir)/\" -DLOCALEDIR=\"$(localedir)\" $(AM_CPPFLAGS)
libminiospf_a_CFLAGS = $(LIBNL_CFLAGS) $(AM_CFLAGS)
LDADD = $(LIBINTL)
