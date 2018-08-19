/* riemann/client/udp.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_CLIENT_UDP_H__
#define __MADHOUSE_RIEMANN_CLIENT_UDP_H__

#include <riemann/client.h>
#include <riemann/message.h>
#include <netdb.h>

#ifdef __cplusplus
extern "C" {
#endif

void _riemann_client_connect_setup_udp (riemann_client_t *client,
                                        struct addrinfo *hints);

int _riemann_client_send_message_udp (riemann_client_t *client,
                                      riemann_message_t *message);
riemann_message_t *_riemann_client_recv_message_udp (riemann_client_t *client);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif
