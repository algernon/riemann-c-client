/* riemann/client/tcp.c -- Riemann C client library
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

#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "riemann/client/tcp.h"
#include "riemann/_private.h"

void
_riemann_client_connect_setup_tcp (riemann_client_t *client,
                                   struct addrinfo *hints)
{
  client->send = _riemann_client_send_message_tcp;
  client->recv = _riemann_client_recv_message_tcp;

  hints->ai_socktype = SOCK_STREAM;
}

int
_riemann_client_send_message_tcp (riemann_client_t *client,
                                  riemann_message_t *message)
{
  uint8_t *buffer;
  size_t len;
  ssize_t sent;

  buffer = riemann_message_to_buffer (message, &len);
  if (!buffer)
    return -errno;

  sent = send (client->sock, buffer, len, 0);
  if (sent == -1 || (size_t)sent != len)
    {
      int e = errno;

      free (buffer);
      return -e;
    }
  free (buffer);
  return 0;
}

riemann_message_t *
_riemann_client_recv_message_tcp (riemann_client_t *client)
{
  uint32_t header, len;
  uint8_t *buffer;
  ssize_t received;
  riemann_message_t *message;

  received = recv (client->sock, &header, sizeof (header), MSG_WAITALL);
  if (received != sizeof (header))
    return NULL;
  len = ntohl (header);

  buffer = (uint8_t *) malloc (len);

  received = recv (client->sock, buffer, len, MSG_WAITALL);
  if (received != len)
    {
      int e = errno;

      free (buffer);
      errno = e;
      return NULL;
    }

  message = riemann_message_from_buffer (buffer, len);
  if (message == NULL)
    {
      int e = errno;

      free (buffer);
      errno = e;
      return NULL;
    }
  free (buffer);

  return message;
}
