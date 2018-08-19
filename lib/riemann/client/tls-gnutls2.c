/* riemann/client/tls-gnutls2.c -- Riemann C client library
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

#ifndef GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT
#define GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT -1
#endif

static int
_verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  const gnutls_datum_t *cert_list;
  unsigned int cert_list_size;
  int ret;
  gnutls_x509_crt_t cert;

  ret = gnutls_certificate_verify_peers2 (session, &status);
  if (ret < 0)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (status & GNUTLS_CERT_INVALID ||
      status & GNUTLS_CERT_SIGNER_NOT_FOUND ||
      status & GNUTLS_CERT_REVOKED ||
      status & GNUTLS_CERT_EXPIRED ||
      status & GNUTLS_CERT_NOT_ACTIVATED)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_certificate_type_get (session) != GNUTLS_CRT_X509)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_x509_crt_init (&cert) < 0)
    return GNUTLS_E_CERTIFICATE_ERROR;

  cert_list = gnutls_certificate_get_peers (session, &cert_list_size);
  if (cert_list == NULL)
    return GNUTLS_E_CERTIFICATE_ERROR;

  if (gnutls_x509_crt_import (cert, &cert_list[0], GNUTLS_X509_FMT_DER) < 0)
    return GNUTLS_E_CERTIFICATE_ERROR;

  gnutls_x509_crt_deinit (cert);

  return 0;
}

static void
_tls_handshake_setup (riemann_client_t *client,
                      riemann_client_tls_options_t __attribute__((unused)) *tls_options)
{
#if __GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ > 4
#pragma GCC diagnostic ignored "-Wint-to-pointer-cast"
#endif
  gnutls_transport_set_ptr (client->tls.session,
                            (gnutls_transport_ptr_t) client->sock);

  if (tls_options->handshake_timeout != (unsigned int)GNUTLS_DEFAULT_HANDSHAKE_TIMEOUT)
    {
      struct timeval timeout;

      timeout.tv_sec = tls_options->handshake_timeout / 1000;
      timeout.tv_usec = (tls_options->handshake_timeout % 1000) * 1000;

      riemann_client_set_timeout (client, &timeout);
    }

#if __GNUC__ > 4 || __GNUC__ == 4 && __GNUC_MINOR__ > 4
#pragma GCC diagnostic warning "-Wint-to-pointer-cast"
#endif
}

__attribute__((constructor))
static void
riemann_tls_init ()
{
  gnutls_global_init ();
}

__attribute__((destructor))
static void
riemann_tls_deinit ()
{
  gnutls_global_deinit ();
}
