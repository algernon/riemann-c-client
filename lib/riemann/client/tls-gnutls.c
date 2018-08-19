/* riemann/client/tls-gnutls.c -- Riemann C client library
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
#include <string.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "riemann/_private.h"
#include "riemann/platform.h"

#include "riemann/client/tls.h"

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#if GNUTLS_VERSION_MAJOR == 2 || (GNUTLS_VERSION_MAJOR == 3 && GNUTLS_VERSION_MINOR < 3)
#include "riemann/client/tls-gnutls2.c"
#else
#include "riemann/client/tls-gnutls3.c"
#endif

void
_riemann_client_init_tls (riemann_client_t *client)
{
  client->tls.session = NULL;
  client->tls.creds = NULL;
}

void
_riemann_client_disconnect_tls (riemann_client_t *client)
{
  if (client->send == _riemann_client_send_message_tls)
    {
      if (client->tls.session)
        {
          gnutls_deinit (client->tls.session);
          client->tls.session = NULL;
        }

      if (client->tls.creds)
        {
          gnutls_certificate_free_credentials (client->tls.creds);
          client->tls.creds = NULL;
        }
    }
}

int
_riemann_client_connect_setup_tls (riemann_client_t *client,
                                   struct addrinfo *hints,
                                   va_list aq,
                                   riemann_client_tls_options_t *tls_options)
{
  va_list ap;
  riemann_client_option_t option;

  memset (tls_options, 0, sizeof (riemann_client_tls_options_t));
  tls_options->handshake_timeout = GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT;

  client->send = _riemann_client_send_message_tls;
  client->recv = _riemann_client_recv_message_tls;

  hints->ai_socktype = SOCK_STREAM;

  va_copy (ap, aq);

  option = (riemann_client_option_t) va_arg (ap, int);
  do
    {
      switch (option)
        {
        case RIEMANN_CLIENT_OPTION_NONE:
          break;

        case RIEMANN_CLIENT_OPTION_TLS_CA_FILE:
          tls_options->cafn = va_arg (ap, char *);
          break;

        case RIEMANN_CLIENT_OPTION_TLS_CERT_FILE:
          tls_options->certfn = va_arg (ap, char *);
          break;

        case RIEMANN_CLIENT_OPTION_TLS_KEY_FILE:
          tls_options->keyfn = va_arg (ap, char *);
          break;

        case RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT:
          tls_options->handshake_timeout = va_arg (ap, unsigned int);
          break;

        case RIEMANN_CLIENT_OPTION_TLS_PRIORITIES:
          tls_options->priorities = va_arg (ap, char *);
          break;

        default:
          va_end (ap);
          return -EINVAL;
        }

      if (option != RIEMANN_CLIENT_OPTION_NONE)
        option = (riemann_client_option_t) va_arg (ap, int);
    }
  while (option != RIEMANN_CLIENT_OPTION_NONE);
  va_end (ap);

  if (!tls_options->cafn || !tls_options->certfn || !tls_options->keyfn)
    {
      return -EINVAL;
    }

  return 0;
}

int
_riemann_client_connect_tls_handshake (riemann_client_t *client,
                                       riemann_client_tls_options_t *tls_options)
{
  int e;

  gnutls_certificate_allocate_credentials (&(client->tls.creds));
  gnutls_certificate_set_x509_trust_file (client->tls.creds, tls_options->cafn,
                                          GNUTLS_X509_FMT_PEM);
#if GNUTLS_VERSION_MAJOR > 2 || (GNUTLS_VERSION_MAJOR == 2 && GNUTLS_VERSION_MINOR >= 10)
  gnutls_certificate_set_verify_function (client->tls.creds,
                                          _verify_certificate_callback);
#endif

  gnutls_certificate_set_x509_key_file (client->tls.creds,
                                        tls_options->certfn, tls_options->keyfn,
                                        GNUTLS_X509_FMT_PEM);

  gnutls_init (&client->tls.session, GNUTLS_CLIENT);

  if (tls_options->priorities)
    {
      if (gnutls_priority_set_direct (client->tls.session, tls_options->priorities, NULL) != GNUTLS_E_SUCCESS)
        {
          e = -1;
          goto end;
        }
    }
  else
    gnutls_set_default_priority (client->tls.session);

  gnutls_credentials_set (client->tls.session, GNUTLS_CRD_CERTIFICATE,
                          client->tls.creds);

  _tls_handshake_setup (client, tls_options);

  do {
    e = gnutls_handshake (client->tls.session);
  } while (e < 0 && e != GNUTLS_E_AGAIN && gnutls_error_is_fatal (e) == 0);

#if GNUTLS_VERSION_MAJOR == 2 && GNUTLS_VERSION_MINOR < 10
  if (e == 0 &&
      _verify_certificate_callback (client->tls.session) != 0)
      e = -1;
#endif

 end:
  if (e != 0)
    {
      gnutls_deinit (client->tls.session);
      gnutls_certificate_free_credentials (client->tls.creds);

      client->tls.session = NULL;
      client->tls.creds = NULL;

      return -EPROTO;
    }

  return 0;
}

int
_riemann_client_send_message_tls (riemann_client_t *client,
                                  riemann_message_t *message)
{
  uint8_t *buffer;
  size_t len;
  ssize_t sent;

  buffer = riemann_message_to_buffer (message, &len);
  if (!buffer)
    return -errno;

  sent = gnutls_record_send (client->tls.session, buffer, len);
  if (sent < 0 || (size_t)sent != len)
    {
      free (buffer);
      return -EPROTO;
    }
  free (buffer);
  return 0;
}

riemann_message_t *
_riemann_client_recv_message_tls (riemann_client_t *client)
{
  uint32_t header, len;
  uint8_t *buffer;
  ssize_t received;
  riemann_message_t *message;

  received = gnutls_record_recv (client->tls.session, &header, sizeof (header));
  if (received != sizeof (header))
    {
      errno = EPROTO;
      return NULL;
    }
  len = ntohl (header);

  buffer = (uint8_t *) malloc (len);

  received = gnutls_record_recv (client->tls.session, buffer, len);
  if (received != len)
    {
      free (buffer);
      errno = EPROTO;
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
