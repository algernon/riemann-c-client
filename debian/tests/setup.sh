#! /bin/sh
set -e
install -d "${AUTOPKGTEST_TMP}"/riemann
cp lib/riemann/_private.h "${AUTOPKGTEST_TMP}"/riemann
VERSION="$(grep AC_INIT configure.ac | sed -e "s/^.*\[riemann-c-client\], \[\([0-9\.]*\)\].*/\1/")"
cat >"${AUTOPKGTEST_TMP}"/riemann/platform.h <<EOF
#define HAVE_GNUTLS 1
#define HAVE_VERSIONING 1
#define PACKAGE_STRING "riemann-c-client ${VERSION}"
#define PACKAGE_VERSION "${VERSION}"
EOF

run_test() {
    testName="$1"
    gcc $(pkg-config --cflags riemann-client check) -I. -I${AUTOPKGTEST_TMP} \
        tests/check_${testName}.c -o ${AUTOPKGTEST_TMP}/check_${testName} \
        $(pkg-config --libs riemann-client check) -ldl
    ${AUTOPKGTEST_TMP}/check_${testName}
}
