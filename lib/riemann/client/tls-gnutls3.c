/* riemann/client/tls-gnutls3.c -- Riemann C client library
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

static int
_verify_certificate_callback (gnutls_session_t session)
{
  unsigned int status;
  int ret;
  const char *hostname;
  gnutls_typed_vdata_st data[2];

  hostname = (const char *) gnutls_session_get_ptr (session);

  memset (data, 0, sizeof (data));

  data[0].type = GNUTLS_DT_DNS_HOSTNAME;
  data[0].data = (unsigned char *) hostname;

  data[1].type = GNUTLS_DT_KEY_PURPOSE_OID;
  data[1].data = (unsigned char *) GNUTLS_KP_TLS_WWW_SERVER;

  ret = gnutls_certificate_verify_peers (session, data, 2,
                                         &status);
  if (ret < 0 || status != 0)
    return GNUTLS_E_CERTIFICATE_ERROR;

   return 0;
}

static void
_tls_handshake_setup (riemann_client_t *client,
                      riemann_client_tls_options_t *tls_options)
{
  gnutls_transport_set_int (client->tls.session, client->sock);
  gnutls_handshake_set_timeout (client->tls.session,
                                tls_options->handshake_timeout);
}
