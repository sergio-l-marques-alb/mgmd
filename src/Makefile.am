#include $(top_srcdir)/build/export.var
ACLOCAL_AMFLAGS = -I m4

lib_LTLIBRARIES = libmgmd.la

libmgmd_la_SOURCES = ptin_mgmd_defs.h ptin_mgmd_inet_defs.h ptin_utils_inet_addr_api.h ptin_mgmd_features.h  \
	ptin_mgmd_avl.c ptin_mgmd_avl.h ptin_mgmd_avl_api.h ptin_mgmd_avl_util.c                                            \
	ptin_mgmd_ctrl.c ptin_mgmd_ctrl.h                                           \
	ptin_mgmd_osapi.c ptin_mgmd_osapi.h                                         \
	ptin_mgmd_querytimer.c ptin_mgmd_querytimer.h                               \
	ptin_mgmd_statistics.c ptin_mgmd_statistics.h                               \
	ptin_mgmd_cnfgr.c ptin_mgmd_cnfgr.h                                         \
	ptin_mgmd_cfg_api.c ptin_mgmd_cfg_api.h                                     \
	ptin_mgmd_eventqueue.c ptin_mgmd_eventqueue.h                               \
	ptin_mgmd_proxytimer.c ptin_mgmd_proxytimer.h                               \
	ptin_mgmd_service_api.c ptin_mgmd_service_api.h                             \
	ptin_timer_api.c ptin_timer_api.h                                           \
	ptin_mgmd_sll.c ptin_mgmd_sll_api.h                                         \
	ptin_mgmd_db.c ptin_mgmd_db.h                                               \
	ptin_mgmd_util.c ptin_mgmd_util.h                                           \
	ptin_mgmd_logger.c ptin_mgmd_logger.h                                       \
	ptin_mgmd_cfg.c ptin_mgmd_cfg.h                                             \
	ptin_mgmd_grouptimer.c ptin_mgmd_grouptimer.h                               \
	ptin_mgmd_querier.c ptin_mgmd_querier.h                                     \
	ptin_mgmd_sourcetimer.c ptin_mgmd_sourcetimer.h                             \
	ptin_utils_inet_addr.c                                                      \
	ptin_mgmd_core.c ptin_mgmd_core.h                                           \
	ptin_mgmd_api.c ptin_mgmd_api.h                                             \
	ptin_mgmd_specificquery.c ptin_mgmd_specificquery.h                         \
	ptin_mgmd_groupsourcespecifictimer.c ptin_mgmd_groupsourcespecifictimer.h   \
	ptin_mgmd_routercmtimer.c ptin_mgmd_routercmtimer.h                         \
	ptin_mgmd_proxycmtimer.c ptin_mgmd_proxycmtimer.h     				    	 \
	ptin_fifo_api.c ptin_fifo_api.h   							        		 \
	ptin_mgmd_whitelist.c ptin_mgmd_whitelist.h   

libmgmd_la_CFLAGS = $(CFLAGS) $(MGMD_CFLAGS) -I./
libmgmd_la_LDFLAGS = $(LDFLAGS) -g -avoid-version

sbin_PROGRAMS = mgmd.cli
mgmd_cli_SOURCES = emulator.c
mgmd_cli_CFLAGS = $(CFLAGS) $(MGMD_CFLAGS)
mgmd_cli_LDADD = $(LD_PATH) $(LIBS) $(LDADD) ./libmgmd.la $(MGMD_LIBS)

if ENABLE_PTIN_BINARY
sbin_PROGRAMS += mgmd
mgmd_SOURCES = ptin_mgmd_api.c
mgmd_CFLAGS = $(CFLAGS) $(MGMD_CFLAGS)
mgmd_LDADD = $(LD_PATH) $(LIBS) $(LDADD) ./libmgmd.la $(MGMD_LIBS)
endif

#libmgmd_la_LIBADD = 
pkginclude_HEADERS = ptin_mgmd_eventqueue.h ptin_mgmd_ctrl.h ptin_mgmd_defs.h ptin_mgmd_api.h ptin_mgmd_inet_defs.h

