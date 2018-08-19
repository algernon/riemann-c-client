#include <riemann/attribute.h>
#include <riemann/event.h>

START_TEST (test_riemann_event_new)
{
  riemann_event_t *event;

  event = riemann_event_new ();
  ck_assert (event != NULL);

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_free)
{
  errno = 0;
  riemann_event_free (NULL);
  ck_assert_errno (-errno, EINVAL);
}
END_TEST

START_TEST (test_riemann_event_set)
{
  riemann_event_t *event;

  ck_assert_errno (riemann_event_set (NULL), EINVAL);

  event = riemann_event_new ();
  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_NONE) == 0);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_TIME, (int64_t) 1234,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_time, 1);
  ck_assert_int_eq (event->time, 1234);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_TIME_MICROS, (int64_t) 123456,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_time_micros, 1);
  ck_assert_int_eq (event->time_micros, 123456);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_STATE, "ok",
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert (event->state != NULL);
  ck_assert_str_eq (event->state, "ok");

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_SERVICE, "test",
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert (event->service != NULL);
  ck_assert_str_eq (event->service, "test");

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_HOST, "localhost",
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert (event->host != NULL);
  ck_assert_str_eq (event->host, "localhost");

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_DESCRIPTION, "something",
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert (event->description != NULL);
  ck_assert_str_eq (event->description, "something");

  ck_assert_errno (riemann_event_set (event, RIEMANN_EVENT_FIELD_TAGS,
                                      "tag-1", "tag-2", NULL,
                                      RIEMANN_EVENT_FIELD_NONE), 0);
  ck_assert_int_eq (event->n_tags, 2);
  ck_assert_str_eq (event->tags[0], "tag-1");
  ck_assert_str_eq (event->tags[1], "tag-2");

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_TTL, (float) 1,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_ttl, 1);
  ck_assert_float_eq (event->ttl, (float) 1);

  ck_assert_errno
    (riemann_event_set (event, RIEMANN_EVENT_FIELD_ATTRIBUTES,
                        riemann_attribute_create ("key-1", "value-1"),
                        riemann_attribute_create ("key-2", "value-2"),
                        NULL,
                        RIEMANN_EVENT_FIELD_NONE), 0);
  ck_assert_int_eq (event->n_attributes, 2);
  ck_assert_str_eq (event->attributes[0]->key, "key-1");
  ck_assert_str_eq (event->attributes[1]->value, "value-2");

  ck_assert_errno
    (riemann_event_set (event, RIEMANN_EVENT_FIELD_ATTRIBUTES,
                        riemann_attribute_create ("key-3", "value-3"),
                        NULL,
                        RIEMANN_EVENT_FIELD_NONE), 0);
  ck_assert_int_eq (event->n_attributes, 1);
  ck_assert_str_eq (event->attributes[0]->key, "key-3");
  ck_assert_str_eq (event->attributes[0]->value, "value-3");

  ck_assert_errno
    (riemann_event_set (event, RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
                        "key-4", "value-4",
                        "key-5", "value-5",
                        NULL,
                        RIEMANN_EVENT_FIELD_NONE), 0);
  ck_assert_int_eq (event->n_attributes, 2);
  ck_assert_str_eq (event->attributes[0]->key, "key-4");
  ck_assert_str_eq (event->attributes[1]->value, "value-5");

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_METRIC_S64,
                                (int64_t) 12345,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_metric_sint64, 1);
  ck_assert_int_eq (event->metric_sint64, 12345);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_METRIC_D,
                                (double) 1.5,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_metric_d, 1);
  ck_assert_float_eq (event->metric_d, 1.5);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_METRIC_F,
                                (float) 1.5,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert_int_eq (event->has_metric_f, 1);
  ck_assert_float_eq (event->metric_f, 1.5);

  ck_assert_errno (riemann_event_set (event, RIEMANN_EVENT_FIELD_METRIC_F * 2,
                                      0,
                                      RIEMANN_EVENT_FIELD_NONE), EPROTO);

  ck_assert (riemann_event_set (event, RIEMANN_EVENT_FIELD_SERVICE,
                                NULL,
                                RIEMANN_EVENT_FIELD_NONE) == 0);
  ck_assert (event->service == NULL);

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_set_one)
{
  riemann_event_t *event;

  event = riemann_event_new ();

  ck_assert (riemann_event_set_one (event, TIME, (int64_t) 1234) == 0);
  ck_assert_int_eq (event->has_time, 1);
  ck_assert_int_eq (event->time, 1234);

  ck_assert (riemann_event_set_one (event, TIME_MICROS, (int64_t) 123456) == 0);
  ck_assert_int_eq (event->has_time_micros, 1);
  ck_assert_int_eq (event->time_micros, 123456);

  ck_assert (riemann_event_set_one (event, HOST, "localhost") == 0);
  ck_assert_str_eq (event->host, "localhost");

  ck_assert (riemann_event_set_one (event, TAGS, "tag-1", "tag-2", NULL) == 0);
  ck_assert_str_eq (event->tags[0], "tag-1");
  ck_assert_str_eq (event->tags[1], "tag-2");

  ck_assert (riemann_event_set_one (event, HOST, "localhost2") == 0);
  ck_assert_str_eq (event->host, "localhost2");

  ck_assert (riemann_event_set_one (event, TAGS, "tag-3", NULL) == 0);
  ck_assert_int_eq (event->n_tags, 1);
  ck_assert_str_eq (event->tags[0], "tag-3");

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_create)
{
  riemann_event_t *event;

  event = riemann_event_create (RIEMANN_EVENT_EMPTY);
  ck_assert (event != NULL);
  riemann_event_free (event);

  event = riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                                RIEMANN_EVENT_FIELD_SERVICE, "test",
                                RIEMANN_EVENT_FIELD_NONE);
  ck_assert (event != NULL);
  ck_assert_str_eq (event->host, "localhost");
  ck_assert_str_eq (event->service, "test");
  riemann_event_free (event);

  event = riemann_event_create (255);
  ck_assert (event == NULL);
  ck_assert_errno (-errno, EPROTO);
}
END_TEST

START_TEST (test_riemann_event_tag_add)
{
  riemann_event_t *event;

  event = riemann_event_new ();

  ck_assert_errno (riemann_event_tag_add (NULL, NULL), EINVAL);
  ck_assert_errno (riemann_event_tag_add (event, NULL), EINVAL);

  ck_assert_errno (riemann_event_tag_add (event, "test-tag"), 0);

  ck_assert_int_eq (event->n_tags, 1);
  ck_assert_str_eq (event->tags[0], "test-tag");

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_attribute_add)
{
  riemann_event_t *event;

  event = riemann_event_new ();

  ck_assert_errno (riemann_event_attribute_add (NULL, NULL), EINVAL);
  ck_assert_errno (riemann_event_attribute_add (event, NULL), EINVAL);

  ck_assert_errno (riemann_event_attribute_add
                   (event, riemann_attribute_create ("test-key", "value")), 0);

  ck_assert_int_eq (event->n_attributes, 1);
  ck_assert_str_eq (event->attributes[0]->key, "test-key");

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_string_attribute_add)
{
  riemann_event_t *event;

  event = riemann_event_new ();

  ck_assert_errno (riemann_event_string_attribute_add (NULL, NULL, NULL),
                   EINVAL);
  ck_assert_errno (riemann_event_string_attribute_add (event, "key", NULL),
                   EINVAL);
  ck_assert_errno (riemann_event_string_attribute_add (event, NULL, "value"),
                   EINVAL);

  ck_assert_errno (riemann_event_string_attribute_add
                   (event, "test-key", "value"), 0);

  ck_assert_int_eq (event->n_attributes, 1);
  ck_assert_str_eq (event->attributes[0]->key, "test-key");

  riemann_event_free (event);
}
END_TEST

START_TEST (test_riemann_event_clone)
{
  riemann_event_t *event, *clone;

  ck_assert (riemann_event_clone (NULL) == NULL);
  ck_assert_errno (-errno, EINVAL);

  event = riemann_event_create (RIEMANN_EVENT_FIELD_HOST, "localhost",
                                RIEMANN_EVENT_FIELD_SERVICE, "test",
                                RIEMANN_EVENT_FIELD_TIME, (int64_t) 1234,
                                RIEMANN_EVENT_FIELD_TIME_MICROS, (int64_t) 123456,
                                RIEMANN_EVENT_FIELD_STATE, "ok",
                                RIEMANN_EVENT_FIELD_DESCRIPTION, "something",
                                RIEMANN_EVENT_FIELD_TAGS, "tag-1", "tag-2", NULL,
                                RIEMANN_EVENT_FIELD_TTL, (float) 1,
                                RIEMANN_EVENT_FIELD_ATTRIBUTES,
                                riemann_attribute_create ("key-1", "value-1"),
                                riemann_attribute_create ("key-2", "value-2"),
                                NULL,
                                RIEMANN_EVENT_FIELD_METRIC_S64, (int64_t) 12345,
                                RIEMANN_EVENT_FIELD_NONE);
  clone = riemann_event_clone (event);

  ck_assert (clone != NULL);
  ck_assert (clone != event);

  ck_assert (clone->host != event->host);
  ck_assert_str_eq (clone->host, event->host);
  ck_assert (clone->service != event->service);
  ck_assert_str_eq (clone->service, event->service);
  ck_assert_int_eq (clone->time, event->time);
  ck_assert_int_eq (clone->time_micros, event->time_micros);
  ck_assert (clone->state != event->state);
  ck_assert_str_eq (clone->state, event->state);
  ck_assert (clone->description != event->description);
  ck_assert_str_eq (clone->description, event->description);
  ck_assert_int_eq (clone->metric_sint64, event->metric_sint64);

  ck_assert (clone->tags != NULL);
  ck_assert_int_eq (clone->n_tags, event->n_tags);
  ck_assert (clone->tags[0] != event->tags[0]);
  ck_assert_str_eq (clone->tags[0], event->tags[0]);

  ck_assert (clone->attributes != NULL);
  ck_assert_int_eq (clone->n_attributes, event->n_attributes);
  ck_assert (clone->attributes[0] != event->attributes[0]);
  ck_assert_str_eq (clone->attributes[0]->key,
                    event->attributes[0]->key);

  riemann_event_free (event);
  riemann_event_free (clone);
}
END_TEST

static TCase *
test_riemann_events (void)
{
  TCase *test_events;

  test_events = tcase_create ("Events");
  tcase_add_test (test_events, test_riemann_event_new);
  tcase_add_test (test_events, test_riemann_event_free);
  tcase_add_test (test_events, test_riemann_event_set);
  tcase_add_test (test_events, test_riemann_event_set_one);
  tcase_add_test (test_events, test_riemann_event_tag_add);
  tcase_add_test (test_events, test_riemann_event_attribute_add);
  tcase_add_test (test_events, test_riemann_event_string_attribute_add);
  tcase_add_test (test_events, test_riemann_event_create);
  tcase_add_test (test_events, test_riemann_event_clone);

  return test_events;
}
