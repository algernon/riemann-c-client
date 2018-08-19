/* riemann/message.c -- Riemann C client library
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

#include <riemann/message.h>

#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>

riemann_message_t *
riemann_message_new (void)
{
  riemann_message_t *message;

  message = (riemann_message_t *)malloc (sizeof (riemann_message_t));
  msg__init (message);

  return message;
}

void
riemann_message_free (riemann_message_t *message)
{
  if (!message)
    {
      errno = EINVAL;
      return;
    }

  msg__free_unpacked ((Msg *)message, NULL);
}

int
riemann_message_set_events_n (riemann_message_t *message,
                              size_t n_events,
                              riemann_event_t **events)
{
  if (!message)
    return -EINVAL;

  if (n_events < 1)
    return -ERANGE;

  if (!events)
    return -EINVAL;

  if (message->events)
    {
      size_t i;

      for (i = 0; i < message->n_events; i++)
        riemann_event_free (message->events[i]);

      free (message->events);
    }

  message->n_events = n_events;
  message->events = events;
  return 0;
}

static riemann_event_t **
_riemann_message_combine_events (riemann_event_t **events,
                                 riemann_event_t *event, size_t *n_events,
                                 va_list aq)
{
  size_t alloced;
  va_list ap;

  /* We do not do any sanity checking of arguments here, because
     everywhere this function is called from, the arguments are
     guaranteed to be valid. */

  alloced = *n_events;

  va_copy (ap, aq);

  do
    {
      if (*n_events >= alloced)
        {
          alloced *= 2;
          events = (riemann_event_t **)
            realloc (events, sizeof (riemann_event_t *) * alloced);
        }

      event = va_arg (ap, riemann_event_t *);
      events[*n_events] = event;
      if (event)
        (*n_events)++;
    }
  while (event != NULL);

  va_end (ap);

  return events;
}

int
riemann_message_set_events_va (riemann_message_t *message, va_list aq)
{
  size_t n_events = 1;
  riemann_event_t **events, **nevents, *event;
  va_list ap;

  if (!message)
    return -EINVAL;

  va_copy (ap, aq);
  event = va_arg (ap, riemann_event_t *);
  if (!event)
    {
      va_end (ap);
      return -ERANGE;
    }

  events = (riemann_event_t **) malloc (sizeof (riemann_event_t *));

  events[0] = event;
  nevents = _riemann_message_combine_events (events, events[0], &n_events, ap);
  va_end (ap);

  /* This cannot fail, because all arguments are guaranteed to be
     valid by this point, and there is no other error path in the
     called function. */
  return riemann_message_set_events_n (message, n_events, nevents);
}

int
riemann_message_set_events (riemann_message_t *message, ...)
{
  int r;
  va_list ap;

  va_start (ap, message);
  r = riemann_message_set_events_va (message, ap);
  va_end (ap);

  return r;
}

int
riemann_message_append_events_n (riemann_message_t *message,
                                 size_t n_events,
                                 riemann_event_t **events)
{
  size_t n, start;

  if (!message)
    return -EINVAL;

  if (n_events < 1)
    return -ERANGE;

  if (!events)
    return -EINVAL;

  start = message->n_events;
  message->n_events += n_events;
  message->events = (riemann_event_t **)
    realloc (message->events,
             sizeof (riemann_event_t *) * message->n_events);

  for (n = 0; n < n_events; n++)
    message->events[n + start] = events[n];

  free (events);

  return 0;
}

int
riemann_message_append_events_va (riemann_message_t *message, va_list aq)
{
  riemann_event_t *event, **events, **nevents;
  size_t n_events = 1;
  va_list ap;

  if (!message)
    return -EINVAL;

  va_copy (ap, aq);

  event = va_arg (ap, riemann_event_t *);
  if (!event)
    {
      va_end (ap);
      return -ERANGE;
    }

  events = (riemann_event_t **) malloc (sizeof (riemann_event_t *));
  events[0] = event;
  nevents = _riemann_message_combine_events(events, events[0], &n_events, ap);
  va_end (ap);

  return riemann_message_append_events_n (message, n_events, nevents);
}

int
riemann_message_append_events (riemann_message_t *message, ...)
{
  int r;
  va_list ap;

  va_start (ap, message);
  r = riemann_message_append_events_va (message, ap);
  va_end (ap);

  return r;
}

riemann_message_t *
riemann_message_create_with_events_va (riemann_event_t *event, va_list aq)
{
  riemann_message_t *message;
  riemann_event_t **events;
  va_list ap;
  size_t n_events = 1;

  if (!event)
    {
      errno = EINVAL;
      return NULL;
    }

  message = riemann_message_new ();

  events = (riemann_event_t **) malloc (sizeof (riemann_event_t *));
  events[0] = event;

  va_copy (ap, aq);
  events = _riemann_message_combine_events (events, event, &n_events, ap);
  va_end (ap);

  /* This cannot fail, because all arguments are guaranteed to be
     valid by this point, and there is no other error path in the
     called function. */
  riemann_message_set_events_n (message, n_events, events);

  return message;
}

riemann_message_t *
riemann_message_create_with_events (riemann_event_t *event, ...)
{
  riemann_message_t *message;
  va_list ap;

  va_start (ap, event);
  message = riemann_message_create_with_events_va (event, ap);
  va_end (ap);

  return message;
}

int
riemann_message_set_query (riemann_message_t *message,
                           riemann_query_t *query)
{
  if (!message || !query)
    return -EINVAL;

  if (message->query)
    riemann_query_free (message->query);
  message->query = query;

  return 0;
}

riemann_message_t *
riemann_message_create_with_query (riemann_query_t *query)
{
  riemann_message_t *message;

  if (!query)
    {
      errno = EINVAL;
      return NULL;
    }

  message = riemann_message_new ();

  /* Setting the query cannot fail here, because neither message, nor
     query can be NULL at this point. */
  riemann_message_set_query (message, query);

  return message;
}

uint8_t *
riemann_message_to_buffer (riemann_message_t *message, size_t *len)
{
  size_t l;
  struct buff
  {
    uint32_t header;
    uint8_t data[0];
  } *buff;

  if (!message)
    {
      errno = EINVAL;
      return NULL;
    }

  l = msg__get_packed_size (message) + sizeof (buff->header);
  buff = (struct buff *) malloc (l);
  msg__pack (message, buff->data);

  buff->header = htonl (l - sizeof (buff->header));

  if (len)
    *len = l;

  return (uint8_t *)buff;
}

riemann_message_t *
riemann_message_from_buffer (uint8_t *buffer, size_t len)
{
  if (!buffer || len == 0)
    {
      errno = EINVAL;
      return NULL;
    }

  errno = EPROTO;
  return msg__unpack (NULL, len, buffer);
}

riemann_message_t *
riemann_message_clone (const riemann_message_t *message)
{
  riemann_message_t *clone;
  size_t n;

  if (!message)
    {
      errno = EINVAL;
      return NULL;
    }

  clone = riemann_message_new ();
  clone->has_ok = message->has_ok;
  clone->ok = message->ok;

  if (message->error)
    clone->error = strdup (message->error);

  if (message->query)
    clone->query = riemann_query_clone (message->query);

  clone->n_events = message->n_events;
  clone->events = (riemann_event_t **)
    malloc (sizeof (riemann_event_t *) * clone->n_events);
  for (n = 0; n < clone->n_events; n++)
    clone->events[n] = riemann_event_clone (message->events[n]);

  return clone;
}

size_t
riemann_message_get_packed_size (riemann_message_t *message)
{
  if (!message)
    {
      errno = EINVAL;
      return 0;
    }

  return msg__get_packed_size (message);
}
