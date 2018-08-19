/* riemann/event.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_EVENT_H__
#define __MADHOUSE_RIEMANN_EVENT_H__ 1

#include <riemann/proto/riemann.pb-c.h>
#include <riemann/attribute.h>
#include <stdarg.h>

typedef Event riemann_event_t;

typedef enum
  {
    RIEMANN_EVENT_FIELD_NONE = 0,
    RIEMANN_EVENT_EMPTY = 0,
    RIEMANN_EVENT_FIELD_TIME,
    RIEMANN_EVENT_FIELD_STATE,
    RIEMANN_EVENT_FIELD_SERVICE,
    RIEMANN_EVENT_FIELD_HOST,
    RIEMANN_EVENT_FIELD_DESCRIPTION,
    RIEMANN_EVENT_FIELD_TAGS,
    RIEMANN_EVENT_FIELD_TTL,
    RIEMANN_EVENT_FIELD_ATTRIBUTES,
    RIEMANN_EVENT_FIELD_METRIC_S64,
    RIEMANN_EVENT_FIELD_METRIC_D,
    RIEMANN_EVENT_FIELD_METRIC_F,

    RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
    RIEMANN_EVENT_FIELD_TIME_MICROS
  } riemann_event_field_t;

#ifdef __cplusplus
extern "C" {
#endif

riemann_event_t *riemann_event_new (void);
riemann_event_t *riemann_event_create (riemann_event_field_t field, ...);
riemann_event_t *riemann_event_create_va (riemann_event_field_t field,
                                          va_list aq);
riemann_event_t *riemann_event_clone (const riemann_event_t *event);
void riemann_event_free (riemann_event_t *event);

int riemann_event_set (riemann_event_t *event, ...);
int riemann_event_set_va (riemann_event_t *event,
                          riemann_event_field_t first_field, va_list aq);
#define riemann_event_set_one(event, field, ...)                        \
  riemann_event_set (event, RIEMANN_EVENT_FIELD_##field, __VA_ARGS__,   \
                     RIEMANN_EVENT_FIELD_NONE)

int riemann_event_tag_add (riemann_event_t *event, const char *tag);
int riemann_event_attribute_add (riemann_event_t *event,
                                 riemann_attribute_t *attrib);
int riemann_event_string_attribute_add (riemann_event_t *event,
                                        const char *key,
                                        const char *value);

#ifdef __cplusplus
}
#endif

#endif
