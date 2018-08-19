/* riemann/message.h -- Riemann C client library
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

#ifndef __MADHOUSE_RIEMANN_MESSAGE_H__
#define __MADHOUSE_RIEMANN_MESSAGE_H__ 1

#include <riemann/proto/riemann.pb-c.h>
#include <riemann/event.h>
#include <riemann/query.h>

typedef Msg riemann_message_t;

#ifdef __cplusplus
extern "C" {
#endif

riemann_message_t *riemann_message_new (void);
riemann_message_t *riemann_message_create_with_events (riemann_event_t *event, ...);
riemann_message_t *riemann_message_create_with_events_va (riemann_event_t *event, va_list aq);
riemann_message_t *riemann_message_create_with_query (riemann_query_t *query);
riemann_message_t *riemann_message_clone (const riemann_message_t *message);
void riemann_message_free (riemann_message_t *message);

int riemann_message_set_events (riemann_message_t *message, ...);
int riemann_message_set_events_va (riemann_message_t *message, va_list aq);
int riemann_message_set_events_n (riemann_message_t *message,
                                  size_t n_events,
                                  riemann_event_t **events);

int riemann_message_append_events (riemann_message_t *message, ...);
int riemann_message_append_events_va (riemann_message_t *message, va_list aq);
int riemann_message_append_events_n (riemann_message_t *message,
                                     size_t n_events,
                                     riemann_event_t **events);

int riemann_message_set_query (riemann_message_t *message,
                               riemann_query_t *query);

uint8_t *riemann_message_to_buffer (riemann_message_t *message, size_t *len);
riemann_message_t *riemann_message_from_buffer (uint8_t *buffer, size_t len);
size_t riemann_message_get_packed_size (riemann_message_t *message);

#ifdef __cplusplus
}
#endif

#endif
