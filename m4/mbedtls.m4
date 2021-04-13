AC_DEFUN([LIB_MBEDTLS], [
  save_LIBS="$LIBS"
  LIBS=""
  MBEDTLS_LIBS=""
  unset ac_cv_search_mbedtls_ssl_init
  AC_SEARCH_LIBS([mbedtls_ssl_init], [mbedtls],
                 [have_mbedtls=yes
                  MBEDTLS_LIBS="$LIBS -lmbedtls -lmbedcrypto -lmbedx509"],
                 [have_mbedtls=no],
                 [-lmbedtls -lmbedcrypto -lmbedx509])
  LIBS="$save_LIBS"
  CPPFLAGS_SAVE=$CPPFLAGS
  CPPFLAGS="$CPPFLAGS $MBEDTLS_CFLAGS"
  AC_CHECK_HEADERS([mbedtls/ssl.h], [], [have_mbedtls=no])
  CPPFLAGS="$CPPFLAGS_SAVE"
  AC_SUBST(MBEDTLS_CFLAGS)
  AC_SUBST(MBEDTLS_LIBS)
]
)
