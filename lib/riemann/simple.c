/* riemann/simple.c -- Riemann C client library
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

#include <netdb.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "riemann/_private.h"
#include <riemann/simple.h>

int
riemann_send_va (riemann_client_t *client,
                 riemann_event_field_t field,
                 va_list aq)
{
  riemann_message_t *message;
  riemann_event_t *event;
  va_list ap;
  int e;

  if (!client)
    return -ENOTCONN;

  event = riemann_event_new ();

  va_copy (ap, aq);
  if ((e = riemann_event_set_va (event, field, ap)) != 0)
    {
      va_end (ap);
      riemann_event_free (event);

      return e;
    }
  va_end (ap);

  /* No need to check errors here, because event is guaranteed to be
  non-NULL here, and the only way this can fail, is an OOM, in which
  case we will crash anyway. */
  message = riemann_message_create_with_events (event, NULL);

  return riemann_client_send_message_oneshot (client, message);
}

int
riemann_send (riemann_client_t *client,
              riemann_event_field_t field, ...)
{
  va_list ap;
  int e;

  va_start (ap, field);
  e = riemann_send_va (client, field, ap);
  va_end (ap);

  return e;
}

riemann_message_t *
riemann_query (riemann_client_t *client, const char *query)
{
  int e;

  e = riemann_client_send_message_oneshot
    (client, riemann_message_create_with_query (riemann_query_new (query)));
  if (e != 0)
    {
      errno = -e;
      return NULL;
    }

  return riemann_client_recv_message (client);
}

riemann_message_t *
riemann_communicate (riemann_client_t *client,
                     riemann_message_t *message)
{
  int r;

  if (!client)
    {
      if (message)
        riemann_message_free (message);

      errno = ENOTCONN;
      return NULL;
    }

  if (!message)
    {
      errno = EINVAL;
      return NULL;
    }

  r = riemann_client_send_message_oneshot (client, message);
  if (r != 0)
    {
      errno = -r;
      return NULL;
    }

  if (client->srv_addr->ai_socktype == SOCK_DGRAM)
    {
      riemann_message_t *response;

      response = riemann_message_new ();
      response->has_ok = 1;
      response->ok = 1;

      return response;
    }

  return riemann_client_recv_message (client);
}

riemann_message_t *
riemann_communicate_query (riemann_client_t *client,
                           const char *query_string)
{
  if (client && client->srv_addr->ai_socktype == SOCK_DGRAM)
    {
      errno = ENOTSUP;
      return NULL;
    }

  return riemann_communicate
    (client,
     riemann_message_create_with_query
     (riemann_query_new (query_string)));
}

riemann_message_t *
riemann_communicate_event (riemann_client_t *client,
                           riemann_event_field_t field, ...)
{
  va_list ap;
  riemann_event_t *event;

  va_start (ap, field);
  event = riemann_event_create_va (field, ap);
  va_end (ap);

  if (!event)
    return NULL;

  return riemann_communicate
    (client,
     riemann_message_create_with_events (event, NULL));
}
