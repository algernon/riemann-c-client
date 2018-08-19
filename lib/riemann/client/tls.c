/* riemann/client/tls.c -- Riemann C client library
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

#include "riemann/_private.h"
#include "riemann/platform.h"

#include "riemann/client/tls.h"

#if HAVE_GNUTLS

#include <gnutls/gnutls.h>
#include <gnutls/x509.h>

#include "riemann/client/tls-gnutls.c"

#else /* !HAVE_GNUTLS */

void
_riemann_client_init_tls (riemann_client_t __attribute__((unused)) *client)
{
}

void
_riemann_client_disconnect_tls (riemann_client_t __attribute__((unused)) *client)
{
}

int
_riemann_client_connect_setup_tls (riemann_client_t __attribute__((unused)) *client,
                                   struct addrinfo __attribute__((unused)) *hints,
                                   va_list __attribute__((unused)) aq,
                                   riemann_client_tls_options_t __attribute__((unused)) *tls_options)
{
  return -ENOTSUP;
}

int
_riemann_client_connect_tls_handshake (riemann_client_t __attribute__((unused)) *client,
                                       riemann_client_tls_options_t __attribute__((unused)) *tls_options)
{
  return -ENOSYS;
}

#endif
