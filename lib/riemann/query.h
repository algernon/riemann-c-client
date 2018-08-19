/* riemann/query.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_QUERY_H__
#define __MADHOUSE_RIEMANN_QUERY_H__ 1

#include <riemann/proto/riemann.pb-c.h>

typedef Query riemann_query_t;

#ifdef __cplusplus
extern "C" {
#endif

riemann_query_t *riemann_query_new (const char *string);
riemann_query_t *riemann_query_clone (const riemann_query_t *query);
void riemann_query_free (riemann_query_t *query);

int riemann_query_set_string (riemann_query_t *query, const char *string);

#ifdef __cplusplus
}
#endif

#endif
