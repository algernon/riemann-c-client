/* riemann/event.c -- Riemann C client library
 * Copyright (C) 2013-2017  Gergely Nagy <algernon@madhouse-project.org>
 *
 * This library is free software: you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public License
 * as published by the Free Software Foundation, either version 3 of
 * the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

#include <riemann/event.h>

#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

riemann_event_t *
riemann_event_new (void)
{
  riemann_event_t *event;

  event = (riemann_event_t *)malloc (sizeof (riemann_event_t));
  event__init (event);
  return event;
}

void
riemann_event_free (riemann_event_t *event)
{
  if (!event)
    {
      errno = EINVAL;
      return;
    }

  event__free_unpacked (event, NULL);
}

static void
_riemann_event_set_string (char **str, char *value)
{
  if (*str)
    free (*str);
  if (value)
    *str = strdup (value);
  else
    *str = NULL;
}

int
riemann_event_set_va (riemann_event_t *event,
                      riemann_event_field_t first_field, va_list aq)
{
  va_list ap;
  riemann_event_field_t field;

  if (!event)
    return -EINVAL;

  va_copy (ap, aq);
  field = first_field;
  do
    {
      switch (field)
        {
        case RIEMANN_EVENT_FIELD_NONE:
          break;

        case RIEMANN_EVENT_FIELD_TIME:
          event->time = (int64_t) va_arg (ap, int64_t);
          event->has_time = 1;
          break;

        case RIEMANN_EVENT_FIELD_TIME_MICROS:
          event->time_micros = (int64_t) va_arg (ap, int64_t);
          event->has_time_micros = 1;
        break;

        case RIEMANN_EVENT_FIELD_STATE:
          _riemann_event_set_string (&event->state, va_arg (ap, char *));
          break;

        case RIEMANN_EVENT_FIELD_SERVICE:
          _riemann_event_set_string (&event->service, va_arg (ap, char *));
          break;

        case RIEMANN_EVENT_FIELD_HOST:
          _riemann_event_set_string (&event->host, va_arg (ap, char *));
          break;

        case RIEMANN_EVENT_FIELD_DESCRIPTION:
          _riemann_event_set_string (&event->description, va_arg (ap, char *));
          break;

        case RIEMANN_EVENT_FIELD_TAGS:
          {
            char *tag;
            size_t n;

            for (n = 0; n < event->n_tags; n++)
              free (event->tags[n]);
            if (event->tags)
              free (event->tags);
            event->tags = NULL;
            event->n_tags = 0;

            while ((tag = va_arg (ap, char *)) != NULL)
              {
                event->tags = (char **)
                  realloc (event->tags, sizeof (char *) * (event->n_tags + 1));
                event->tags[event->n_tags] = strdup (tag);
                event->n_tags++;
              }

            break;
          }

        case RIEMANN_EVENT_FIELD_TTL:
          event->ttl = (float) va_arg (ap, double);
          event->has_ttl = 1;
          break;

        case RIEMANN_EVENT_FIELD_ATTRIBUTES:
          {
            riemann_attribute_t *attrib;
            size_t n;

            for (n = 0; n < event->n_attributes; n++)
              riemann_attribute_free (event->attributes[n]);
            if (event->attributes)
              free (event->attributes);
            event->attributes = NULL;
            event->n_attributes = 0;

            while ((attrib = va_arg (ap, riemann_attribute_t *)) != NULL)
              {
                event->attributes = (riemann_attribute_t **)
                  realloc (event->attributes,
                           sizeof (riemann_attribute_t *) * (event->n_attributes + 1));
                event->attributes[event->n_attributes] = attrib;
                event->n_attributes++;
              }

            break;
          }

        case RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES:
          {
            const char *key, *value;
            size_t n;

            for (n = 0; n < event->n_attributes; n++)
              riemann_attribute_free (event->attributes[n]);
            if (event->attributes)
              free (event->attributes);
            event->attributes = NULL;
            event->n_attributes = 0;

            while ((key = va_arg (ap, const char *)) != NULL)
              {
                value = va_arg (ap, const char *);

                event->attributes = (riemann_attribute_t **)
                  realloc (event->attributes,
                           sizeof (riemann_attribute_t *) * (event->n_attributes + 1));
                event->attributes[event->n_attributes] =
                  riemann_attribute_create (key, value);
                event->n_attributes++;
              }

            break;
          }

        case RIEMANN_EVENT_FIELD_METRIC_S64:
          event->metric_sint64 = va_arg (ap, int64_t);
          event->has_metric_sint64 = 1;
          break;

        case RIEMANN_EVENT_FIELD_METRIC_D:
          event->metric_d = va_arg (ap, double);
          event->has_metric_d = 1;
          break;

        case RIEMANN_EVENT_FIELD_METRIC_F:
          event->metric_f = (float) va_arg (ap, double);
          event->has_metric_f = 1;
          break;

        default:
          va_end (ap);
          return -EPROTO;
        }

      if (field != RIEMANN_EVENT_FIELD_NONE)
        field = (riemann_event_field_t) va_arg (ap, int);
    }
  while (field != RIEMANN_EVENT_FIELD_NONE);
  va_end (ap);

  return 0;
}

int
riemann_event_set (riemann_event_t *event, ...)
{
  va_list ap;
  int r;
  riemann_event_field_t first_field;

  va_start (ap, event);
  first_field = (riemann_event_field_t) va_arg (ap, int);
  r = riemann_event_set_va (event, first_field, ap);
  va_end (ap);
  return r;
}

int
riemann_event_tag_add (riemann_event_t *event, const char *tag)
{
  if (!event || !tag)
    return -EINVAL;

  event->tags = (char **)
    realloc (event->tags, sizeof (char *) * (event->n_tags + 1));
  event->tags[event->n_tags] = strdup (tag);
  event->n_tags++;

  return 0;
}

int
riemann_event_attribute_add (riemann_event_t *event,
                             riemann_attribute_t *attrib)
{
  if (!event || !attrib)
    return -EINVAL;

  event->attributes = (riemann_attribute_t **)
    realloc (event->attributes,
             sizeof (riemann_attribute_t *) * (event->n_attributes + 1));
  event->attributes[event->n_attributes] = attrib;
  event->n_attributes++;

  return 0;
}

int
riemann_event_string_attribute_add (riemann_event_t *event,
                                    const char *key,
                                    const char *value)
{
  if (!key || !value)
    return -EINVAL;

  return riemann_event_attribute_add (event,
                                      riemann_attribute_create (key, value));
}

riemann_event_t *
riemann_event_create_va (riemann_event_field_t field, va_list aq)
{
  va_list ap;
  riemann_event_t *event;
  int e;

  event = riemann_event_new ();

  va_copy (ap, aq);
  if ((e = riemann_event_set_va (event, field, ap)) != 0)
    {
      va_end (ap);
      riemann_event_free (event);
      errno = -e;
      return NULL;
    }
  va_end (ap);

  return event;
}

riemann_event_t *
riemann_event_create (riemann_event_field_t field, ...)
{
  riemann_event_t *event;
  va_list ap;

  va_start (ap, field);
  event = riemann_event_create_va (field, ap);
  va_end (ap);

  return event;
}

riemann_event_t *
riemann_event_clone (const riemann_event_t *event)
{
  riemann_event_t *clone;
  size_t n;

  if (!event)
    {
      errno = EINVAL;
      return NULL;
    }

  clone = riemann_event_new ();

  /* Copy non-pointer properties */
  clone->time = event->time;
  clone->time_micros = event->time_micros;
  clone->ttl = event->ttl;
  clone->metric_sint64 = event->metric_sint64;
  clone->metric_d = event->metric_d;
  clone->metric_f = event->metric_f;

  /* Copy strings */
  if (event->state)
    clone->state = strdup (event->state);
  if (event->host)
    clone->host = strdup (event->host);
  if (event->service)
    clone->service = strdup (event->service);
  if (event->description)
    clone->description = strdup (event->description);

  /* Copy deeper structures */
  clone->n_tags = event->n_tags;
  clone->tags = (char **) malloc (sizeof (char *) * clone->n_tags);
  for (n = 0; n < clone->n_tags; n++)
    clone->tags[n] = strdup (event->tags[n]);

  clone->n_attributes = event->n_attributes;
  clone->attributes = (riemann_attribute_t **)
    malloc (sizeof (riemann_attribute_t *) *
            clone->n_attributes);
  for (n = 0; n < clone->n_attributes; n++)
    clone->attributes[n] = riemann_attribute_clone (event->attributes[n]);

  return clone;
}
