/* riemann/riemann-client.c -- Riemann C client library
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

#include <riemann/riemann-client.h>

#include <errno.h>
#include <inttypes.h>
#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <getopt.h>
#include <time.h>

#include "riemann/platform.h"

#if HAVE_JSON_C
#include <json.h>
#endif

static int
version_display (int __attribute__((unused)) argc, char __attribute__((unused)) *argv[])
{
  printf ("%s\n", riemann_client_version_string ());
  return EXIT_SUCCESS;
}

static void
help_display (const char *app_name, void (*contents)(void))
{
  version_display (0, NULL);
  printf ("Usage: %s COMMAND [options...] [HOST] [PORT]\n"
          "\n", app_name);
  contents();
  printf ("\n"
          "The HOST and PORT arguments are optional, and they default to\n"
          "\"localhost\" and 5555, respectively.\n"
          "\n"
          "Report riemann-c-client bugs to https://git.madhouse-project.org/algernon/riemann-c-client/issues\n");
}

#include "cmd-send.c"
#include "cmd-query.c"

static void
help_generic (void)
{
  printf ("Available commands: send and query.\n"
          "\n");
  help_send ();
  printf ("\n");
  help_query ();
}

static int
display_help_generic (int __attribute__((unused)) argc,
                      char *argv[])
{
  help_display (argv[0], help_generic);
  return EXIT_SUCCESS;
}

typedef int (*cmd_t) (int argc, char *argv[]);

static struct
{
  const char *command;
  cmd_t handler;
  int (*cmp) (const char *s1, const char *s2);
} command_map[] = {
  { "send", client_send, strcasecmp },
  { "query", client_query, strcasecmp },
  { "--version", version_display, strcasecmp },
  { "-V", version_display, strcmp },
  { "--help", display_help_generic, strcasecmp },
  { "-?", display_help_generic, strcmp },
  { NULL, NULL, NULL },
};

int
main (int argc, char *argv[])
{
  const char *command = NULL;
  int i = 0;

  if (argc < 2)
    {
      fprintf (stderr, "Not enough arguments!\n");
      display_help_generic (argc, argv);
      exit (EXIT_FAILURE);
    }

  command = argv[1];

  while (command_map[i].command != NULL)
    {
      if (command_map[i].cmp (command, command_map[i].command) == 0)
        return command_map[i].handler (argc, argv);
      i++;
    }

  fprintf (stderr, "Unknown command: '%s'\n", command);
  help_display (argv[0], help_generic);
  return EXIT_FAILURE;
}
