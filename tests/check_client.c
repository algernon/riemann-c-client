#include <riemann/client.h>

START_TEST (test_riemann_client_new)
{
  riemann_client_t *client;

  client = riemann_client_new ();
  ck_assert (client != NULL);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_client_free)
{
  errno = 0;
  riemann_client_free (NULL);
  ck_assert_errno (-errno, EINVAL);
}
END_TEST

START_TEST (test_riemann_client_connect)
{
  riemann_client_t *client;

  client = riemann_client_new ();

  ck_assert_errno (riemann_client_connect (NULL, RIEMANN_CLIENT_TCP,
                                           "127.0.0.1", 5555), EINVAL);
  ck_assert_errno (riemann_client_connect (client, RIEMANN_CLIENT_NONE,
                                           "127.0.0.1", 5555), EINVAL);
  ck_assert_errno (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                           NULL, 5555), EINVAL);
  ck_assert_errno (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                           "127.0.0.1", -1), ERANGE);

  ck_assert (client != NULL);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_client_get_fd)
{
  ck_assert_errno (riemann_client_get_fd (NULL), EINVAL);
}
END_TEST

START_TEST (test_riemann_client_set_timeout)
{
  struct timeval timeout;
  riemann_client_t *client;

  timeout.tv_sec = 5;
  timeout.tv_usec = 42;

  ck_assert_errno (riemann_client_set_timeout (NULL, NULL), EINVAL);
  ck_assert_errno (riemann_client_set_timeout (NULL, &timeout), EINVAL);

  client = riemann_client_new ();
  ck_assert_errno (riemann_client_set_timeout (client, &timeout), EINVAL);
  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_client_disconnect)
{
  ck_assert_errno (riemann_client_disconnect (NULL), ENOTCONN);
}
END_TEST

static TCase *
test_riemann_client (void)
{
  TCase *test_client;

  test_client = tcase_create ("Client");
  tcase_add_test (test_client, test_riemann_client_new);
  tcase_add_test (test_client, test_riemann_client_free);
  tcase_add_test (test_client, test_riemann_client_connect);
  tcase_add_test (test_client, test_riemann_client_disconnect);
  tcase_add_test (test_client, test_riemann_client_get_fd);
  tcase_add_test (test_client, test_riemann_client_set_timeout);

  return test_client;
}
