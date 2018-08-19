/* riemann/attribute.c -- Riemann C client library
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

#include <riemann/attribute.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>

riemann_attribute_t *
riemann_attribute_new (void)
{
  riemann_attribute_t *attrib;

  attrib = (riemann_attribute_t *)
    malloc (sizeof (riemann_attribute_t));
  attribute__init (attrib);
  return attrib;
}

void
riemann_attribute_free (riemann_attribute_t *attrib)
{
  if (!attrib)
    {
      errno = EINVAL;
      return;
    }

  attribute__free_unpacked (attrib, NULL);
}

int
riemann_attribute_set_key (riemann_attribute_t *attrib, const char *key)
{
  if (!attrib || !key)
    return -EINVAL;

  if (attrib->key)
    free (attrib->key);
  attrib->key = strdup (key);

  return 0;
}

int
riemann_attribute_set_value (riemann_attribute_t *attrib, const char *value)
{
  if (!attrib || !value)
    return -EINVAL;

  if (attrib->value)
    free (attrib->value);
  attrib->value = strdup (value);

  return 0;
}

int
riemann_attribute_set (riemann_attribute_t *attrib,
                       const char *key, const char *value)
{
  int e;

  if ((e = riemann_attribute_set_key (attrib, key)) != 0)
    return e;
  if ((e = riemann_attribute_set_value (attrib, value)) != 0)
    return e;

  return 0;
}

riemann_attribute_t *
riemann_attribute_create (const char *key, const char *value)
{
  riemann_attribute_t *attrib;

  /* All of these calls can only fail if run out of memory, in which
     case, the library will crash anyway. We only set the key or the
     value when they were supplied to this function, so that branch is
     guarded against, too. */

  attrib = riemann_attribute_new ();

  if (key)
    riemann_attribute_set_key (attrib, key);

  if (value)
    riemann_attribute_set_value (attrib, value);

  return attrib;
}

riemann_attribute_t *
riemann_attribute_clone (const riemann_attribute_t *attrib)
{
  if (!attrib)
    {
      errno = EINVAL;
      return NULL;
    }

  return riemann_attribute_create (attrib->key, attrib->value);
}
