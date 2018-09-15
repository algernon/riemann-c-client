#define _GNU_SOURCE

#include <check.h>
#include <errno.h>
#include <netdb.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

#include <riemann/client.h>
#include <riemann/simple.h>
#include "riemann/platform.h"
#include "riemann/_private.h"

#if HAVE_GNUTLS
#include <gnutls/gnutls.h>
#endif

#include "tests.h"
#include "mocks.c"
#include "mocks.h"

char *RIEMANN_HOST;
uint16_t RIEMANN_TCP_PORT;
uint16_t RIEMANN_UDP_PORT;
uint16_t RIEMANN_TLS_PORT;

static int
network_tests_enabled (void)
{
  char *env_flag = getenv ("RCC_NETWORK_TESTS");

  if (!env_flag || !*env_flag || env_flag[0] == '0')
    return 0;

  return 1;
}

static int
_mock_setsockopt (int sockfd __attribute__((unused)),
                  int level __attribute__((unused)),
                  int optname,
                  const void *optval __attribute__((unused)),
                  socklen_t optlen __attribute__((unused)))
{
  if (optname == SO_RCVTIMEO)
    {
      errno = ENOSYS;
      return -1;
    }

  return 0;
}

make_mock (setsockopt, int,
           int sockfd, int level, int optname,
           const void *optval, socklen_t optlen)
{
  STUB (setsockopt, sockfd, level, optname, optval, optlen);
}

make_mock (riemann_message_to_buffer, uint8_t *,
          riemann_message_t *message, size_t *len)
{
  STUB (riemann_message_to_buffer, message, len);
}

static uint8_t *
_mock_message_to_buffer ()
{
  errno = EPROTO;
  return NULL;
}

START_TEST(test_net_riemann_client_connect)
{
  riemann_client_t *client;

  client = riemann_client_new ();

  ck_assert_errno (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                           RIEMANN_HOST, 5559), ECONNREFUSED);

  ck_assert (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                     RIEMANN_HOST, RIEMANN_TCP_PORT) == 0);
  ck_assert_errno (riemann_client_disconnect (client), 0);

  ck_assert (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                     RIEMANN_HOST, RIEMANN_TCP_PORT,
                                     RIEMANN_CLIENT_OPTION_NONE) == 0);
  ck_assert_errno (riemann_client_disconnect (client), 0);

  ck_assert_errno (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                           "non-existent.example.com", RIEMANN_TCP_PORT),
                   EADDRNOTAVAIL);

  mock (socket, mock_enosys_int_always_fail);
  ck_assert_errnos (riemann_client_connect (client, RIEMANN_CLIENT_TCP,
                                            RIEMANN_HOST, RIEMANN_TCP_PORT),
                    -e == ENOSYS || -e == EADDRNOTAVAIL );
  restore (socket);

  /** TLS tests **/
#if HAVE_GNUTLS
  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      RIEMANN_CLIENT_OPTION_NONE),
     EINVAL);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      256,
      RIEMANN_CLIENT_OPTION_NONE),
     EINVAL);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
      RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
      RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
      RIEMANN_CLIENT_OPTION_NONE),
     0);
  riemann_client_disconnect (client);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert-invalid.pem",
      RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
      RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
      RIEMANN_CLIENT_OPTION_NONE),
     EPROTO);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TCP_PORT,
      RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
      RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
      RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
      RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT, 1000,
      RIEMANN_CLIENT_OPTION_NONE),
     EPROTO);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
      RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
      RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
      RIEMANN_CLIENT_OPTION_TLS_PRIORITIES, "NONE",
      RIEMANN_CLIENT_OPTION_NONE),
     EPROTO);

  ck_assert_errno
    (riemann_client_connect
     (client, RIEMANN_CLIENT_TLS,
      RIEMANN_HOST, RIEMANN_TLS_PORT,
      RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
      RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
      RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
      RIEMANN_CLIENT_OPTION_TLS_PRIORITIES, "NORMAL:+INVALID",
      RIEMANN_CLIENT_OPTION_NONE),
     EPROTO);
#endif
}
END_TEST

START_TEST (test_net_riemann_client_get_fd)
{
  riemann_client_t *client;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  ck_assert (riemann_client_get_fd (client) != 0);
  riemann_client_free (client);
}
END_TEST

START_TEST (test_net_riemann_client_set_timeout)
{
  struct timeval timeout;
  riemann_client_t *client;
  int fd;

  timeout.tv_sec = 5;
  timeout.tv_usec = 42;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  ck_assert_errno (riemann_client_set_timeout (client, NULL), EINVAL);
  ck_assert_errno (riemann_client_set_timeout (client, &timeout), 0);

  fd = client->sock;
  client->sock = client->sock + 10;

  ck_assert_errno (riemann_client_set_timeout (client, &timeout), EBADF);

  mock (setsockopt, _mock_setsockopt);
  ck_assert_errno (riemann_client_set_timeout (client, &timeout), ENOSYS);
  restore (setsockopt);

  client->sock = fd;

  riemann_client_disconnect (client);

  riemann_client_connect (client, RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);
  ck_assert_errno (riemann_client_set_timeout (client, &timeout), 0);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_net_riemann_client_disconnect)
{
  riemann_client_t *client;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  client->sock++;

  ck_assert_errno (riemann_client_disconnect (client), EBADF);
  client->sock--;
  riemann_client_free (client);
}
END_TEST

START_TEST (test_net_riemann_client_create)
{
  riemann_client_t *client;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, 5559);
  ck_assert (client == NULL);
  ck_assert_errnos (-errno, -e == ECONNREFUSED || -e == EADDRNOTAVAIL);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  ck_assert (client != NULL);
  ck_assert_errno (riemann_client_disconnect (client), 0);
  ck_assert (client != NULL);
  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT,
                                  RIEMANN_CLIENT_OPTION_NONE);
  ck_assert (client != NULL);
  ck_assert_errno (riemann_client_disconnect (client), 0);
  ck_assert (client != NULL);
  riemann_client_free (client);

#if HAVE_GNUTLS
  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  ck_assert (client != NULL);
  ck_assert_errno (riemann_client_disconnect (client), 0);
  ck_assert (client != NULL);
  riemann_client_free (client);
#else
  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  ck_assert (client == NULL);
  ck_assert_errno (-errno, ENOTSUP);
#endif
}
END_TEST

#if HAVE_GNUTLS
make_mock (gnutls_record_send, ssize_t, gnutls_session_t session,
           const void *data, size_t len)
{
  STUB (gnutls_record_send, session, data, len);
}

make_mock (gnutls_record_recv, ssize_t, gnutls_session_t session,
           void *buf, size_t len)
{
  STUB (gnutls_record_recv, session, buf, len);
}

static ssize_t
_mock_gnutls_record_recv_message_part (gnutls_session_t session,
                                       void *buf, size_t len)
{
  static int counter;

  counter++;
  if (counter % 2 == 0)
    {
      errno = ENOSYS;
      return -1;
    }

  return real_gnutls_record_recv (session, buf, len);
}

static ssize_t
_mock_gnutls_record_recv_message_garbage (gnutls_session_t session,
                                          void *buf, size_t len)
{
  static int counter;
  ssize_t res;

  counter++;
  res = real_gnutls_record_recv (session, buf, len);

  if (counter % 2 == 0)
    memset (buf, 128, len);

  return res;
}

START_TEST (test_net_riemann_client_send_message_tls)
{
  riemann_client_t *client;
  riemann_message_t *message;

  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);

  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);

  ck_assert_errno (riemann_client_send_message (NULL, message), ENOTCONN);
  ck_assert_errno (riemann_client_send_message (client, NULL), EINVAL);

  mock (riemann_message_to_buffer, _mock_message_to_buffer);
  ck_assert_errno (riemann_client_send_message (client, message),
                   EPROTO);
  restore (riemann_message_to_buffer);

  ck_assert_errno (riemann_client_send_message (client, message), 0);

  mock (gnutls_record_send, mock_enosys_ssize_t_always_fail);
  ck_assert_errno (riemann_client_send_message (client, message), EPROTO);
  restore (gnutls_record_send);

  riemann_client_free (client);

  riemann_message_free (message);
}
END_TEST

START_TEST (test_net_riemann_client_recv_message_tls)
{
  riemann_client_t *client;
  riemann_message_t *message, *response = NULL;

  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);

  riemann_client_send_message (client, message);
  ck_assert ((response = riemann_client_recv_message (client)) != NULL);
  ck_assert_int_eq (response->ok, 1);
  riemann_message_free (response);
  riemann_client_free (client);

  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  riemann_client_send_message (client, message);
  mock (gnutls_record_recv, mock_enosys_ssize_t_always_fail);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, EPROTO);
  restore (gnutls_record_recv);
  riemann_client_free (client);

  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  riemann_client_send_message (client, message);
  mock (gnutls_record_recv, _mock_gnutls_record_recv_message_part);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, EPROTO);
  restore (recv);
  riemann_client_free (client);

  client = riemann_client_create
    (RIEMANN_CLIENT_TLS,
     RIEMANN_HOST, RIEMANN_TLS_PORT,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "tests/data/cacert.pem",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "tests/data/client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "tests/data/client.key",
     RIEMANN_CLIENT_OPTION_NONE);
  riemann_client_send_message (client, message);
  mock (gnutls_record_recv, _mock_gnutls_record_recv_message_garbage);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, EPROTO);
  restore (gnutls_record_recv);
  riemann_client_free (client);

  riemann_message_free (message);
}
END_TEST
#endif

START_TEST (test_net_riemann_client_send_message)
{
  riemann_client_t *client, *client_fresh;
  riemann_message_t *message;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);

  ck_assert_errno (riemann_client_send_message (NULL, message), ENOTCONN);
  ck_assert_errno (riemann_client_send_message (client, NULL), EINVAL);

  client_fresh = riemann_client_new ();
  ck_assert_errno (riemann_client_send_message (client_fresh, message), ENOTCONN);
  riemann_client_free (client_fresh);

  mock (riemann_message_to_buffer, _mock_message_to_buffer);
  ck_assert_errno (riemann_client_send_message (client, message),
                   EPROTO);
  restore (riemann_message_to_buffer);

  ck_assert_errno (riemann_client_send_message (client, message), 0);

  mock (send, mock_enosys_ssize_t_always_fail);
  ck_assert_errno (riemann_client_send_message (client, message), ENOSYS);
  restore (send);

  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);

  mock (riemann_message_to_buffer, _mock_message_to_buffer);
  ck_assert_errno (riemann_client_send_message (client, message),
                   EPROTO);
  restore (riemann_message_to_buffer);

  ck_assert_errno (riemann_client_send_message (client, message), 0);

  mock (sendto, mock_enosys_ssize_t_always_fail);
  ck_assert_errno (riemann_client_send_message (client, message), ENOSYS);
  restore (sendto);

  riemann_client_free (client);

  riemann_message_free (message);
}
END_TEST

static ssize_t
_mock_recv_message_part (int sockfd, void *buf, size_t len, int flags)
{
  static int counter;

  counter++;
  if (counter % 2 == 0)
    {
      errno = ENOSYS;
      return -1;
    }

  return real_recv (sockfd, buf, len, flags);
}

static ssize_t
_mock_recv_message_garbage (int sockfd, void *buf, size_t len, int flags)
{
  static int counter;
  ssize_t res;

  counter++;
  res = real_recv (sockfd, buf, len, flags);

  if (counter % 2 == 0)
    memset (buf, 128, len);

  return res;
}

START_TEST (test_net_riemann_client_recv_message)
{
  riemann_client_t *client, *client_fresh;
  riemann_message_t *message, *response = NULL;

  errno = 0;
  ck_assert (riemann_client_recv_message (NULL) == NULL);
  ck_assert_errno (-errno, ENOTCONN);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);

  client_fresh = riemann_client_new ();
  ck_assert (riemann_client_recv_message (client_fresh) == NULL);
  ck_assert_errno (-errno, ENOTCONN);
  riemann_client_free (client_fresh);

  riemann_client_send_message (client, message);
  ck_assert ((response = riemann_client_recv_message (client)) != NULL);
  ck_assert_int_eq (response->ok, 1);
  riemann_message_free (response);
  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  riemann_client_send_message (client, message);
  mock (recv, mock_enosys_ssize_t_always_fail);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, ENOSYS);
  restore (recv);
  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  riemann_client_send_message (client, message);
  mock (recv, _mock_recv_message_part);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, ENOSYS);
  restore (recv);
  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  riemann_client_send_message (client, message);
  mock (recv, _mock_recv_message_garbage);
  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, EPROTO);
  restore (recv);
  riemann_client_free (client);

  client = riemann_client_create (RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);

  ck_assert (riemann_client_recv_message (client) == NULL);
  ck_assert_errno (-errno, ENOTSUP);

  riemann_client_free (client);

  riemann_message_free (message);
}
END_TEST

START_TEST (test_net_riemann_client_send_message_oneshot)
{
  riemann_client_t *client, *client_fresh;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  ck_assert_errno (riemann_client_send_message_oneshot
                   (NULL, riemann_message_create_with_events
                    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                                           RIEMANN_EVENT_FIELD_STATE, "ok",
                                           RIEMANN_EVENT_FIELD_NONE),
                     NULL)), ENOTCONN);
  ck_assert_errno (riemann_client_send_message (client, NULL), EINVAL);

  client_fresh = riemann_client_new ();
  ck_assert_errno (riemann_client_send_message_oneshot
                   (client_fresh, riemann_message_create_with_events
                    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                                           RIEMANN_EVENT_FIELD_STATE, "ok",
                                           RIEMANN_EVENT_FIELD_NONE),
                     NULL)), ENOTCONN);
  riemann_client_free (client_fresh);

  ck_assert_errno (riemann_client_send_message_oneshot
                   (client, riemann_message_create_with_events
                    (riemann_event_create (RIEMANN_EVENT_FIELD_SERVICE, "test",
                                           RIEMANN_EVENT_FIELD_STATE, "ok",
                                           RIEMANN_EVENT_FIELD_NONE),
                     NULL)), 0);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_simple_send)
{
  riemann_client_t *client;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);

  ck_assert_errno (riemann_send (NULL, RIEMANN_EVENT_FIELD_NONE), ENOTCONN);

  ck_assert_errno (riemann_send (client, 255), EPROTO);

  ck_assert_errno (riemann_send (client,
                                 RIEMANN_EVENT_FIELD_SERVICE, "test-simple",
                                 RIEMANN_EVENT_FIELD_STATE, "ok",
                                 RIEMANN_EVENT_FIELD_NONE),
                   0);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_simple_query)
{
  riemann_client_t *client;
  riemann_message_t *response;

  ck_assert (riemann_query (NULL, "service = \"test-simple\"") == NULL);
  ck_assert_errno (-errno, ENOTCONN);

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);

  riemann_send (client,
                RIEMANN_EVENT_FIELD_SERVICE, "test-simple",
                RIEMANN_EVENT_FIELD_STATE, "ok",
                RIEMANN_EVENT_FIELD_NONE);

  response = riemann_query (client, "service = \"test-simple\"");

  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);

  riemann_message_free (response);
  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_simple_communicate)
{
  riemann_client_t *client, *dummy_client;
  riemann_message_t *message, *response;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);

  ck_assert (riemann_communicate (NULL, NULL) == NULL);
  ck_assert_errno (-errno, ENOTCONN);

  ck_assert (riemann_communicate (client, NULL) == NULL);
  ck_assert_errno (-errno, EINVAL);

  ck_assert (riemann_communicate (NULL, message) == NULL);
  ck_assert_errno (-errno, ENOTCONN);

  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);
  dummy_client = riemann_client_new ();
  ck_assert (riemann_communicate (dummy_client, message) == NULL);
  ck_assert_errno (-errno, ENOTCONN);
  riemann_client_free (dummy_client);

  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);
  response = riemann_communicate (client, message);
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  riemann_message_free (response);

  response = riemann_communicate
    (client,
     riemann_message_create_with_query
     (riemann_query_new ("true")));
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  ck_assert (response->n_events > 0);
  riemann_message_free (response);

  riemann_client_disconnect (client);
  riemann_client_connect (client, RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);
  response = riemann_communicate (client, message);
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  riemann_message_free (response);
  riemann_client_disconnect (client);

  riemann_client_connect (client, RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate #2",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);
  riemann_message_set_query (message,
                             riemann_query_new ("true"));

  response = riemann_communicate (client, message);
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  ck_assert (response->n_events > 0);
  riemann_message_free (response);
  riemann_client_disconnect (client);

  riemann_client_connect (client, RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);
  message = riemann_message_create_with_events
    (riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                           RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate #2",
                           RIEMANN_EVENT_FIELD_STATE, "ok",
                           RIEMANN_EVENT_FIELD_NONE),
     NULL);
  riemann_message_set_query (message,
                             riemann_query_new ("true"));

  response = riemann_communicate (client, message);
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  ck_assert (response->n_events == 0);
  riemann_message_free (response);
  riemann_client_disconnect (client);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_simple_communicate_query)
{
  riemann_client_t *client;
  riemann_message_t *response;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  response = riemann_communicate_query (client, "true");
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  ck_assert (response->n_events > 0);
  riemann_message_free (response);
  riemann_client_disconnect (client);

  client = riemann_client_create (RIEMANN_CLIENT_UDP, RIEMANN_HOST, RIEMANN_UDP_PORT);
  response = riemann_communicate_query (client, "true");
  ck_assert (response == NULL);
  ck_assert_errno (-errno, ENOTSUP);
  riemann_client_disconnect (client);

  riemann_client_free (client);
}
END_TEST

START_TEST (test_riemann_simple_communicate_event)
{
  riemann_client_t *client;
  riemann_message_t *response;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, RIEMANN_HOST, RIEMANN_TCP_PORT);
  response = riemann_communicate_event
    (client,
     RIEMANN_EVENT_FIELD_HOST, "localhost",
     RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate_event",
     RIEMANN_EVENT_FIELD_STATE, "ok",
     RIEMANN_EVENT_FIELD_NONE);
  ck_assert (response != NULL);
  ck_assert_int_eq (response->ok, 1);
  ck_assert_int_eq (response->n_events, 0);
  riemann_message_free (response);

  response = riemann_communicate_event
    (client,
     256,
     RIEMANN_EVENT_FIELD_NONE);
  ck_assert (response == NULL);
  ck_assert_errno (-errno, EPROTO);

  riemann_send
    (client,
     RIEMANN_EVENT_FIELD_HOST, "localhost",
     RIEMANN_EVENT_FIELD_SERVICE, "test_riemann_simple_communicate_event",
     RIEMANN_EVENT_FIELD_STATE, "ok",
     RIEMANN_EVENT_FIELD_NONE);

  response = riemann_communicate_event (client, RIEMANN_EVENT_FIELD_NONE);
  ck_assert (response != NULL);
  ck_assert (response->has_ok == 1);
  ck_assert (response->ok == 1);
  riemann_message_free (response);

  riemann_client_free (client);
}
END_TEST

static TCase *
test_riemann_network_tests (void)
{
  TCase *tc;

  tc = tcase_create ("Network");
  tcase_add_test (tc, test_net_riemann_client_connect);
  tcase_add_test (tc, test_net_riemann_client_disconnect);
  tcase_add_test (tc, test_net_riemann_client_get_fd);
  tcase_add_test (tc, test_net_riemann_client_set_timeout);

  tcase_add_test (tc, test_net_riemann_client_create);
  tcase_add_test (tc, test_net_riemann_client_send_message);
  tcase_add_test (tc, test_net_riemann_client_send_message_oneshot);
  tcase_add_test (tc, test_net_riemann_client_recv_message);

#if HAVE_GNUTLS
  tcase_add_test (tc, test_net_riemann_client_send_message_tls);
  tcase_add_test (tc, test_net_riemann_client_recv_message_tls);
#endif

  tcase_add_test (tc, test_riemann_simple_send);
  tcase_add_test (tc, test_riemann_simple_query);
  tcase_add_test (tc, test_riemann_simple_communicate);
  tcase_add_test (tc, test_riemann_simple_communicate_query);
  tcase_add_test (tc, test_riemann_simple_communicate_event);

  return tc;
}

int
main (void)
{
  Suite *suite;
  SRunner *runner;
  char *e;

  int nfailed;

  RIEMANN_HOST = getenv ("RIEMANN_HOST");

  e = getenv ("RIEMANN_TCP_PORT");
  if (!e)
    e = "5555";
  RIEMANN_TCP_PORT = atoi(e);

  e = getenv ("RIEMANN_UDP_PORT");
  if (!e)
    e = "5555";
  RIEMANN_UDP_PORT = atoi(e);

  e = getenv ("RIEMANN_TLS_PORT");
  if (!e)
    e = "5554";
  RIEMANN_TLS_PORT = atoi(e);

  suite = suite_create ("Riemann C client library, network-using tests");

  if (network_tests_enabled ())
    suite_add_tcase (suite, test_riemann_network_tests ());

  runner = srunner_create (suite);

  srunner_run_all (runner, CK_ENV);
  nfailed = srunner_ntests_failed (runner);
  srunner_free (runner);

  return (nfailed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
