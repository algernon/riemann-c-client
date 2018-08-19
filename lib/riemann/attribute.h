/* riemann/attribute.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_ATTRIBUTE_H__
#define __MADHOUSE_RIEMANN_ATTRIBUTE_H__ 1

#include <riemann/proto/riemann.pb-c.h>

typedef Attribute riemann_attribute_t;

#ifdef __cplusplus
extern "C" {
#endif

riemann_attribute_t *riemann_attribute_new (void);
riemann_attribute_t *riemann_attribute_clone (const riemann_attribute_t *attrib);
riemann_attribute_t *riemann_attribute_create (const char *key,
                                               const char *value);
void riemann_attribute_free (riemann_attribute_t *attrib);

int riemann_attribute_set_key (riemann_attribute_t *attrib, const char *key);
int riemann_attribute_set_value (riemann_attribute_t *attrib, const char *value);
int riemann_attribute_set (riemann_attribute_t *attrib,
                           const char *key, const char *value);

#ifdef __cplusplus
}
#endif

#endif
