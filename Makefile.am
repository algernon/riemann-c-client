# -- Global settings --
AM_MAKEFLAGS			= --no-print-directory
AM_CFLAGS			= -I${top_srcdir}/lib -I${top_builddir}/lib
ACLOCAL_AMFLAGS			= -Im4

LDADD				= lib/libriemann-client.la

pkgincludedir			= ${includedir}/riemann
protodir			= ${pkgincludedir}/proto

VERSION				= @VERSION@${SNAPSHOT_VERSION}

# -- Libraries --
lib_LTLIBRARIES			= lib/libriemann-client.la

lib_libriemann_client_la_CFLAGS	= ${AM_CFLAGS} ${PROTOBUF_C_CFLAGS} \
				  ${GNUTLS_CFLAGS}
lib_libriemann_client_la_LDFLAGS= \
	${PROTOBUF_C_LIBS}	  \
	${GNUTLS_LIBS}		  \
	-version-info ${LRC_LT_VERSION}
proto_files			= \
	lib/riemann/proto/riemann.pb-c.c  \
	lib/riemann/proto/riemann.pb-c.h
nodist_proto_HEADERS		= \
	lib/riemann/proto/riemann.pb-c.h
pkginclude_HEADERS		= \
	lib/riemann/client.h	  \
	lib/riemann/event.h	  \
	lib/riemann/message.h	  \
	lib/riemann/attribute.h	  \
	lib/riemann/query.h	  \
	lib/riemann/simple.h	  \
	lib/riemann/riemann-client.h
lib_libriemann_client_la_SOURCES= \
	lib/riemann/client.c	  \
	lib/riemann/client/tcp.c  \
	lib/riemann/client/tls.c  \
	lib/riemann/client/udp.c  \
	lib/riemann/event.c	  \
	lib/riemann/message.c	  \
	lib/riemann/attribute.c	  \
	lib/riemann/query.c	  \
	lib/riemann/simple.c
noinst_HEADERS			= \
	lib/riemann/_private.h	  \
	lib/riemann/client/tcp.h  \
	lib/riemann/client/tls.h  \
	lib/riemann/client/udp.h

nodist_lib_libriemann_client_la_SOURCES	= \
	${proto_files}
BUILT_SOURCES = ${proto_files}

CLEANFILES			= ${proto_files}

${proto_files}: ${top_srcdir}/lib/riemann/proto/riemann.proto
	${AM_V_at} ${mkinstalldirs} ${top_builddir}/lib/riemann/proto
	${AM_V_GEN} protoc-c $^ -I${top_srcdir}/lib/riemann/proto --c_out=${top_builddir}/lib/riemann/proto

if HAVE_VERSIONING
lib_libriemann_client_la_LDFLAGS += \
	-Wl,--version-script,$(top_srcdir)/lib/riemann/libriemann.ver
lib_libriemann_client_la_DEPENDENCIES	= ${top_srcdir}/lib/riemann/libriemann.ver
endif

pkgconfigdir			= $(libdir)/pkgconfig
pkgconfig_DATA			= lib/riemann/riemann-client.pc

# -- Testcases --
if HAVE_CHECK
UNIT_TESTS			= tests/check_libriemann \
				  tests/check_symver \
					tests/check_networked
TESTS				= ${UNIT_TESTS}

AM_TESTS_ENVIRONMENT		= \
	CK_FORK=no; test -e tests/data || ln -s ${abs_top_srcdir}/tests/etc tests/data; \
	export CK_FORK;
TESTS_ENVIRONMENT		?= ${AM_TESTS_ENVIRONMENT}

tests/check_%: CFLAGS += ${CHECK_CFLAGS}
tests/check_%: LDADD += ${CHECK_LIBS} -ldl
tests/check_%: LDFLAGS += -no-install

check_PROGRAMS			= ${TESTS}
endif

check_libriemann_srcs		= \
	tests/mocks.h		  \
	tests/mocks.c		  \
	tests/tests.h		  \
	tests/check_library.c	  \
	tests/check_events.c	  \
	tests/check_messages.c	  \
	tests/check_client.c	  \
	tests/check_attributes.c  \
	tests/check_queries.c	  \
	tests/check_libriemann.c

# -- Binaries --
bin_PROGRAMS			= \
	src/riemann-client

src_riemann_client_CFLAGS	= $(AM_CFLAGS) $(JSON_C_CFLAGS) ${PROTOBUF_C_CFLAGS}
src_riemann_client_LDADD	= $(JSON_C_LIBS) $(LDADD)
src_riemann_client_EXTRA_DIST	= \
	src/cmd-send.c		  \
	src/cmd-query.c

# -- Extra files to distribute --
EXTRA_DIST			= README.md NEWS.md LICENSE LICENSE.GPL CODE_OF_CONDUCT.md \
				  lib/riemann/proto/riemann.proto \
				  lib/riemann/libriemann.ver \
				  lib/riemann/riemann-client.pc \
				  ${check_libriemann_srcs} \
				  ${src_riemann_client_EXTRA_DIST} \
				  ${man1_MANS} tests/etc \
				  lib/riemann/client/tls-gnutls.c \
				  lib/riemann/client/tls-gnutls3.c \
				  lib/riemann/client/tls-gnutls2.c

# -- Manual pages --
man1_MANS			 = \
	src/riemann-client.1

# -- Custom targets --
coverage: coverage.info.html

coverage.info.html: coverage.info
	$(AM_V_GEN)genhtml --quiet $^ --output-directory $@

coverage.info: check
	$(AM_V_GEN)lcov --quiet --capture --directory ${top_builddir}/lib --output $@ -b ${top_builddir} && \
		   lcov --quiet --remove $@ '*/lib/riemann/proto/*' -o $@

.PHONY: coverage
CLEANFILES			+= coverage.info

clean-local:
	rm -rf coverage.info.html gmon.out
	find ${top_builddir} -name '*.gcda' -or -name '*.gcno' | xargs rm -f
