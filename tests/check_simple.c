#include <riemann/simple.h>

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
test_riemann_simple (void)
{
  TCase *test_simple;

  test_simple = tcase_create ("Simple");

  if (network_tests_enabled ())
    {
      tcase_add_test (test_simple, test_riemann_simple_send);
      tcase_add_test (test_simple, test_riemann_simple_query);
      tcase_add_test (test_simple, test_riemann_simple_communicate);
      tcase_add_test (test_simple, test_riemann_simple_communicate_query);
      tcase_add_test (test_simple, test_riemann_simple_communicate_event);
    }

  return test_simple;
}
