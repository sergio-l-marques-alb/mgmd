#include $(top_srcdir)/build/export.var
ACLOCAL_AMFLAGS = -I m4

confdir = $(libdir)/pkgconfig
dist_conf_DATA=mgmd.pc

SUBDIRS = src 

#não quero os *.la no SYS_ROOT_DIR
install-exec-hook:
	find $(DESTDIR)$(libdir) -name "*.la"|xargs rm -f

dist-hook:
	cp -Rf build $(distdir)
#	rm -rf $(distdir)/build/export.var
