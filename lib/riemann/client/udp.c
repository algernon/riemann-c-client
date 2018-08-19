/* riemann/client/udp.c -- Riemann C client library
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

#include <stdlib.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>

#include "riemann/client/udp.h"
#include "riemann/_private.h"

void
_riemann_client_connect_setup_udp (riemann_client_t *client,
                                   struct addrinfo *hints)
{
  client->send = _riemann_client_send_message_udp;
  client->recv = _riemann_client_recv_message_udp;

  hints->ai_socktype = SOCK_DGRAM;
}

struct _riemann_buff_w_hdr
{
  uint32_t header;
  uint8_t data[0];
};

int
_riemann_client_send_message_udp (riemann_client_t *client,
                                  riemann_message_t *message)
{
  struct _riemann_buff_w_hdr *buffer;
  size_t len;
  ssize_t sent;

  buffer = (struct _riemann_buff_w_hdr *)
    riemann_message_to_buffer (message, &len);
  if (!buffer)
    return -errno;

  sent = sendto (client->sock, buffer->data, len - sizeof (buffer->header), 0,
                 client->srv_addr->ai_addr, client->srv_addr->ai_addrlen);
  if (sent == -1 || (size_t)sent != len - sizeof (buffer->header))
    {
      int e = errno;

      free (buffer);
      return -e;
    }
  free (buffer);
  return 0;
}

riemann_message_t *
_riemann_client_recv_message_udp (riemann_client_t __attribute__((unused)) *client)
{
  errno = ENOTSUP;
  return NULL;
}
