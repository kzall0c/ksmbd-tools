AM_CFLAGS = -DSYSCONFDIR='"${sysconfdir}"' -DRUNSTATEDIR='"${runstatedir}"' \
            -I$(top_srcdir)/include -I$(top_srcdir)/addshare \
            $(GLIB_CFLAGS) $(LIBNL_CFLAGS) -fno-common

EXTRA_DIST = ksmbd.selftest.8.in \
	     ksmbd.selftest.in \
	     ksmbd.selftest.conf \
	     meson.build

pkgsysconfdir = $(sysconfdir)/ksmbd
dist_pkgsysconf_DATA = ksmbd.selftest.conf

sbin_SCRIPTS = ksmbd.selftest
man_MANS = ksmbd.selftest.8
$(sbin_SCRIPTS) $(man_MANS): %: %.in; @$(in_script) $< >$@

CLEANFILES = $(sbin_SCRIPTS) $(man_MANS)

check_PROGRAMS = ksmbd.selftest-unit
ksmbd_selftest_unit_SOURCES = selftest.c user.c flip.c config.c \
			      $(top_srcdir)/tools/management/user.c \
			      $(top_srcdir)/tools/management/share.c \
			      $(top_srcdir)/tools/management/tree_conn.c \
			      $(top_srcdir)/tools/management/session.c \
			      $(top_srcdir)/tools/config_parser.c \
			      tools_wrap.c
ksmbd_selftest_unit_LDADD = $(top_builddir)/addshare/libaddshare.a \
			    $(top_builddir)/adduser/libadduser.a \
			    $(top_builddir)/control/libcontrol.a \
			    $(top_builddir)/mountd/libmountd.a \
			    $(GLIB_LIBS) $(LIBNL_LIBS) $(PTHREAD_LIBS)

TESTS = ksmbd.selftest-unit
