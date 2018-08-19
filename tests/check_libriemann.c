#define _GNU_SOURCE

#include <check.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include "riemann/platform.h"
#include "tests.h"

static int
network_tests_enabled (void)
{
  struct addrinfo hints;
  struct addrinfo *res, *rp;
  int fd = -1, s;

  char *env_flag = getenv ("RCC_NETWORK_TESTS");

  if (!env_flag || !*env_flag || env_flag[0] == '0')
    return 0;

  memset (&hints, 0, sizeof (struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;

  s = getaddrinfo ("127.0.0.1", "5555", &hints, &res);
  if (s != 0)
    return 0;

  for (rp = res; rp != NULL; rp = rp->ai_next)
    {
      fd = socket (rp->ai_family, rp->ai_socktype, rp->ai_protocol);
      if (fd == -1)
        continue;

      if (connect (fd, rp->ai_addr, rp->ai_addrlen) != -1)
        break;

      close (fd);
    }
  freeaddrinfo (res);

  if (rp == NULL)
    return 0;

  if (fd != -1)
    close (fd);

  return 1;
}

#include "mocks.c"

#include "check_library.c"
#include "check_attributes.c"
#include "check_queries.c"
#include "check_events.c"
#include "check_messages.c"
#include "check_client.c"
#include "check_simple.c"

int
main (void)
{
  Suite *suite;
  SRunner *runner;

  int nfailed;

  suite = suite_create ("Riemann C client library tests");

  suite_add_tcase (suite, test_riemann_library ());
  suite_add_tcase (suite, test_riemann_attributes ());
  suite_add_tcase (suite, test_riemann_queries ());
  suite_add_tcase (suite, test_riemann_events ());
  suite_add_tcase (suite, test_riemann_messages ());
  suite_add_tcase (suite, test_riemann_client ());
  suite_add_tcase (suite, test_riemann_simple ());

  runner = srunner_create (suite);

  srunner_run_all (runner, CK_ENV);
  nfailed = srunner_ntests_failed (runner);
  srunner_free (runner);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
