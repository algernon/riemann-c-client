/* riemann/client.c -- Riemann C client library
 * Copyright (C) 2013-2018  Gergely Nagy <algernon@madhouse-project.org>
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
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <stdarg.h>

#include "riemann/_private.h"
#include "riemann/platform.h"

#include "riemann/client/tcp.h"
#include "riemann/client/tls.h"
#include "riemann/client/udp.h"

const char *
riemann_client_version (void)
{
  return PACKAGE_VERSION;
}

const char *
riemann_client_version_string (void)
{
  return PACKAGE_STRING;
}

#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattribute-alias"
#endif

riemann_client_t *
SYMVER(riemann_client_new) (void)
{
  riemann_client_t *client;

  client = (riemann_client_t *) malloc (sizeof (riemann_client_t));

  client->sock = -1;
  client->srv_addr = NULL;
  client->send = NULL;
  client->recv = NULL;
  _riemann_client_init_tls (client);

  return client;
}

#if HAVE_VERSIONING
riemann_client_t riemann_client_new_1_0 (void) __attribute__((alias("riemann_client_new_default")));

__asm__(".symver riemann_client_new_1_0,riemann_client_new@RIEMANN_C_1.0");
__asm__(".symver riemann_client_new_default,riemann_client_new@@RIEMANN_C_1.10");
#endif

#ifndef __clang__
#pragma GCC diagnostic pop
#endif

int
riemann_client_disconnect (riemann_client_t *client)
{
  if (!client || client->sock == -1)
    return -ENOTCONN;

  _riemann_client_disconnect_tls (client);

  if (close (client->sock) != 0)
    return -errno;
  client->sock = -1;

  if (client->srv_addr)
    freeaddrinfo (client->srv_addr);
  client->srv_addr = NULL;

  return 0;
}

void
riemann_client_free (riemann_client_t *client)
{
  if (!client)
    {
      errno = EINVAL;
      return;
    }

  errno = -riemann_client_disconnect (client);

  free (client);
}

int
riemann_client_get_fd (riemann_client_t *client)
{
  if (!client)
    return -EINVAL;

  return client->sock;
}

int
riemann_client_set_timeout (riemann_client_t *client,
                            struct timeval *timeout)
{
  if (!client || !timeout)
    return -EINVAL;

  if (client->sock < 0)
    return -EINVAL;

  if (setsockopt (client->sock, SOL_SOCKET, SO_SNDTIMEO, timeout,
                  sizeof (struct timeval)) == -1)
    return -errno;
  if (setsockopt (client->sock, SOL_SOCKET, SO_RCVTIMEO, timeout,
                  sizeof (struct timeval)) == -1)
    return -errno;

  return 0;
}

static int
riemann_client_connect_va (riemann_client_t *client,
                           riemann_client_type_t type,
                           const char *hostname, int port,
                           va_list aq)
{
  struct addrinfo hints, *res;
  int sock;
  riemann_client_tls_options_t tls_options;

  if (!client || !hostname)
    return -EINVAL;
  if (port <= 0)
    return -ERANGE;

  memset (&hints, 0, sizeof (hints));
  hints.ai_family = AF_UNSPEC;

  switch (type)
    {
    case RIEMANN_CLIENT_TCP:
      _riemann_client_connect_setup_tcp (client, &hints);
      break;
    case RIEMANN_CLIENT_UDP:
      _riemann_client_connect_setup_udp (client, &hints);
      break;
    case RIEMANN_CLIENT_TLS:
      {
        va_list ap;
        int e;

        va_copy (ap, aq);
        e = _riemann_client_connect_setup_tls (client, &hints, ap, &tls_options);
        va_end (ap);

        if (e != 0)
          return e;

        break;
      }
    default:
      return -EINVAL;
    }

  if (getaddrinfo (hostname, NULL, &hints, &res) != 0)
    return -EADDRNOTAVAIL;

  sock = socket (res->ai_family, res->ai_socktype, 0);
  if (sock == -1)
    {
      int e = errno;

      freeaddrinfo (res);
      return -e;
    }

  ((struct sockaddr_in *)res->ai_addr)->sin_port = htons (port);

  if (connect (sock, res->ai_addr, res->ai_addrlen) != 0)
    {
      int e = errno;

      freeaddrinfo (res);
      close (sock);

      return -e;
    }

  riemann_client_disconnect (client);

  client->sock = sock;
  client->srv_addr = res;

  if (type == RIEMANN_CLIENT_TLS)
    return _riemann_client_connect_tls_handshake (client, &tls_options);

  return 0;
}

#ifndef __clang__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wattribute-alias"
#endif

int
SYMVER(riemann_client_connect) (riemann_client_t *client,
                                riemann_client_type_t type,
                                const char *hostname, int port, ...)
{
  va_list ap;
  int r;

  va_start (ap, port);
  r = riemann_client_connect_va (client, type, hostname, port, ap);
  va_end (ap);
  return r;
}

#if HAVE_VERSIONING
__asm__(".symver riemann_client_connect_default,riemann_client_connect@@RIEMANN_C_1.5");

int
riemann_client_connect_1_0 (riemann_client_t *client,
                            riemann_client_type_t type,
                            const char *hostname, int port)
  __attribute__((alias ("riemann_client_connect_default")));

__asm__(".symver riemann_client_connect_1_0,riemann_client_connect@RIEMANN_C_1.0");
#endif

riemann_client_t *
SYMVER(riemann_client_create) (riemann_client_type_t type,
                               const char *hostname, int port, ...)
{
  riemann_client_t *client;
  int e;
  va_list ap;

  client = riemann_client_new ();

  va_start (ap, port);
  e = riemann_client_connect_va (client, type, hostname, port, ap);
  if (e != 0)
    {
      riemann_client_free (client);
      va_end (ap);
      errno = -e;
      return NULL;
    }
  va_end (ap);

  return client;
}

#if HAVE_VERSIONING
riemann_client_t *
riemann_client_create_1_0 (riemann_client_type_t type,
                           const char *hostname, int port)
  __attribute__((alias ("riemann_client_create_default")));

riemann_client_t *
riemann_client_create_1_5 (riemann_client_type_t type,
                           const char *hostname, int port, ...)
  __attribute__((alias ("riemann_client_create_default")));

__asm__(".symver riemann_client_create_1_0,riemann_client_create@RIEMANN_C_1.0");
__asm__(".symver riemann_client_create_1_5,riemann_client_create@RIEMANN_C_1.5");
__asm__(".symver riemann_client_create_default,riemann_client_create@@RIEMANN_C_1.10");
#endif

#ifndef __clang__
#pragma GCC diagnostic pop
#endif

int
riemann_client_send_message (riemann_client_t *client,
                             riemann_message_t *message)
{
  if (!client)
    return -ENOTCONN;
  if (!message)
    return -EINVAL;

  if (!client->send)
    return -ENOTCONN;

  return client->send (client, message);
}

int
riemann_client_send_message_oneshot (riemann_client_t *client,
                                     riemann_message_t *message)
{
  int ret = 0;

  ret = riemann_client_send_message (client, message);
  riemann_message_free (message);

  return ret;
}

riemann_message_t *
riemann_client_recv_message (riemann_client_t *client)
{
  if (!client || !client->recv)
    {
      errno = ENOTCONN;
      return NULL;
    }

  return client->recv (client);
}
