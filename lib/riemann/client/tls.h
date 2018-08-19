/* riemann/client/tls.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_CLIENT_TLS_H__
#define __MADHOUSE_RIEMANN_CLIENT_TLS_H__

#include <riemann/client.h>
#include <riemann/message.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
  char *cafn;
  char *certfn;
  char *keyfn;
  unsigned int handshake_timeout;
  char *priorities;
} riemann_client_tls_options_t;

void _riemann_client_init_tls (riemann_client_t *client);
void _riemann_client_disconnect_tls (riemann_client_t *client);

int _riemann_client_connect_setup_tls (riemann_client_t *client,
                                       struct addrinfo *hints,
                                       va_list aq,
                                       riemann_client_tls_options_t *tls_options);
int _riemann_client_connect_tls_handshake (riemann_client_t *client,
                                           riemann_client_tls_options_t *tls_options);

int _riemann_client_send_message_tls (riemann_client_t *client,
                                      riemann_message_t *message);
riemann_message_t *_riemann_client_recv_message_tls (riemann_client_t *client);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
