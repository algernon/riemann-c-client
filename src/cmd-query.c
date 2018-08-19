/* riemann-c-client -- Riemann C client library
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

static void
query_dump_event (size_t n, const riemann_event_t *event)
{
  size_t i;
  time_t t;

  if (event->has_time_micros)
    t = event->time_micros/1000000;
  else
    t = event->time;

  printf ("Event #%zu:\n"
          "  time  = %" PRId64 " - %s"
          "  state = %s\n"
          "  service = %s\n"
          "  host = %s\n"
          "  description = %s\n"
          "  ttl = %f\n",
          n,
          t, ctime (&t),
          event->state, event->service, event->host,
          event->description, event->ttl);

  if (event->has_metric_sint64)
    printf ("  metric_sint64 = %" PRId64 "\n", event->metric_sint64);
  if (event->has_metric_d)
    printf ("  metric_d = %f\n", event->metric_d);
  if (event->has_metric_f)
    printf ("  metric_f = %f\n", event->metric_f);

  if (event->tags)
    {
      printf ("  tags = [ ");

      for (i = 0; i < event->n_tags; i++)
        printf ("%s ", event->tags[i]);

      printf ("]\n");
    }

  if (event->attributes)
    {
      printf ("  attributes = {\n");

      for (i = 0; i < event->n_attributes; i++)
        printf ("    %s = %s\n", event->attributes[i]->key,
                event->attributes[i]->value);

      printf ("  }\n");
    }

  printf ("\n");
}

static void
query_dump_events (size_t n, const riemann_event_t **events)
{
  size_t i;

  for (i = 0; i < n; i++)
    query_dump_event (i, events[i]);
}

#if HAVE_JSON_C
static json_object *
query_dump_event_json (size_t __attribute__((unused)) n, const riemann_event_t *event)
{
  json_object *o;
  size_t i;

  o = json_object_new_object ();

  if (event->has_time)
    json_object_object_add (o, "time", json_object_new_int64 (event->time));
  if (event->has_time_micros)
    json_object_object_add (o, "time_micros", json_object_new_int64 (event->time_micros));
  if (event->state)
    json_object_object_add (o, "state", json_object_new_string (event->state));
  if (event->service)
    json_object_object_add (o, "service",
                            json_object_new_string (event->service));
  if (event->host)
    json_object_object_add (o, "host", json_object_new_string (event->host));
  if (event->description)
    json_object_object_add (o, "description",
                            json_object_new_string (event->description));
  if (event->has_ttl)
    json_object_object_add (o, "ttl", json_object_new_double (event->ttl));
  if (event->has_metric_sint64)
    json_object_object_add (o, "metric_sint64",
                            json_object_new_int64 (event->metric_sint64));
  if (event->has_metric_d)
    json_object_object_add (o, "metric_d",
                            json_object_new_double (event->metric_d));
  if (event->has_metric_f)
    json_object_object_add (o, "metric_f",
                            json_object_new_double (event->metric_f));

  if (event->tags)
    {
      json_object *tags;

      tags = json_object_new_array ();

      for (i = 0; i < event->n_tags; i++)
        json_object_array_add (tags, json_object_new_string (event->tags[i]));

      json_object_object_add (o, "tags", tags);
    }

  if (event->attributes)
    {
      json_object *attrs;

      attrs = json_object_new_object ();

      for (i = 0; i < event->n_attributes; i++)
        json_object_object_add (attrs, event->attributes[i]->key,
                                json_object_new_string (event->attributes[i]->value));

      json_object_object_add (o, "attributes", attrs);
    }

  return o;
}

static void
query_dump_events_json (size_t n, const riemann_event_t **events)
{
  size_t i;
  json_object *o;

  o = json_object_new_array ();

  for (i = 0; i < n; i++)
    json_object_array_add (o, query_dump_event_json (i, events[i]));

  printf ("%s\n", json_object_to_json_string_ext (o, JSON_C_TO_STRING_PLAIN));

  json_object_put (o);
}
#else
static void
query_dump_events_json (size_t __attribute__((unused)) n,
                        const riemann_event_t __attribute__((unused)) **events)
{
  fprintf (stderr, "JSON support not available in this build!\n");
  exit (EXIT_FAILURE);
}
#endif

static void
help_query (void)
{
  printf ("Querying events (query command):\n"
          "================================\n"
          "\n"
          "When using the query command, the QUERY argument must immediately follow\n"
          "the command on the command-line:\n"
          " riemann-client query QUERY [HOST] [PORT]\n"
          "\n"
          " Options:\n"
          "  -j, --json                        Output the results as a JSON array.\n"
          "  -T, --tcp                         Send the message over TCP (default).\n"
          "  -G, --tls                         Send the message over TLS.\n"
          "  -o, --option option=value         Set a client option to a given value.\n"
          "  -?, --help                        This help screen.\n");
}

typedef void (*query_func_t) (size_t, const riemann_event_t **);

static int
client_query (int argc, char *argv[])
{
  riemann_message_t *response;
  riemann_client_t *client;
  riemann_client_type_t client_type = RIEMANN_CLIENT_TCP;
  const char *host = "localhost", *query_string = NULL;
  int port = 5555, c, e, exit_status = EXIT_SUCCESS;
  query_func_t dump = query_dump_events;
  struct
  {
    char *cafn;
    char *certfn;
    char *keyfn;
    char *priorities;
  } tls = {NULL, NULL, NULL, NULL};


  while (1)
    {
      int option_index = 0;
      static struct option long_options[] = {
        {"help", no_argument, NULL, '?'},
        {"version", no_argument, NULL, 'V'},
        {"json", no_argument, NULL, 'j'},
        {"tcp", no_argument, NULL, 'T'},
        {"tls", no_argument, NULL, 'G'},
        {"option", required_argument, NULL, 'o'},
        {NULL, 0, NULL, 0}
      };

      c = getopt_long (argc, argv, "?VjTGo:",
                       long_options, &option_index);

      if (c == -1)
        break;

      switch (c)
        {
        case 'T':
          client_type = RIEMANN_CLIENT_TCP;
          break;

        case 'G':
          client_type = RIEMANN_CLIENT_TLS;
          break;

        case 'j':
          dump = query_dump_events_json;
          break;

        case 'o':
          if (strncmp (optarg, "cafile=", strlen ("cafile=")) == 0)
            tls.cafn = &optarg[strlen ("cafile=")];
          else if (strncmp (optarg, "certfile=", strlen ("certfile=")) == 0)
            tls.certfn = &optarg[strlen ("certfile=")];
          else if (strncmp (optarg, "keyfile=", strlen ("keyfile=")) == 0)
            tls.keyfn = &optarg[strlen ("keyfile=")];
          else if (strncmp (optarg, "priorities=", strlen ("priorities=")) == 0)
            tls.priorities = &optarg[strlen ("properties=")];
          else
            {
              fprintf (stderr, "Unknown client option: %s\n", optarg);
              return EXIT_FAILURE;
            }

          break;

        case '?':
          help_display (argv[0], help_query);
          return EXIT_SUCCESS;

        case 'V':
          version_display (0, NULL);
          return EXIT_SUCCESS;

        default:
          fprintf(stderr, "Unknown option: %c\n", c);
          help_display (argv[0], help_query);
          return EXIT_FAILURE;
        }
    }

  optind++;
  if (optind >= argc)
    {
      fprintf (stderr, "The QUERY argument is mandatory!\n");
      help_display (argv[0], help_query);
      return EXIT_FAILURE;
    }

  query_string = argv[optind];

  optind++;

  if (optind < argc)
    {
      host = argv[optind];

      if (optind + 1 < argc)
        port = atoi (argv[optind + 1]);
    }

  if (argc - optind > 2)
    {
      fprintf (stderr, "Too many arguments!\n");
      help_display (argv[0], help_query);
      return EXIT_FAILURE;
    }

  client = riemann_client_create
    (client_type, host, port,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, tls.cafn,
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, tls.certfn,
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, tls.keyfn,
     RIEMANN_CLIENT_OPTION_TLS_PRIORITIES, tls.priorities,
     RIEMANN_CLIENT_OPTION_NONE);
  if (!client)
    {
      fprintf (stderr, "Unable to connect: %s\n", (char *)strerror (errno));
      exit_status = EXIT_FAILURE;
      goto end;
    }

  e = riemann_client_send_message_oneshot
    (client, riemann_message_create_with_query (riemann_query_new (query_string)));
  if (e != 0)
    {
      fprintf (stderr, "Error sending message: %s\n", (char *)strerror (-e));
      exit_status = EXIT_FAILURE;
      goto end;
    }

  response = riemann_client_recv_message (client);
  if (!response)
    {
      fprintf (stderr, "Error when asking for a message receipt: %s\n",
               strerror (errno));
      exit_status = EXIT_FAILURE;
      goto end;
    }

  if (response->ok != 1)
    {
      fprintf (stderr, "Message receipt failed: %s\n", response->error);
      exit_status = EXIT_FAILURE;
      goto end;
    }

  dump (response->n_events, (const riemann_event_t **)response->events);

  riemann_message_free (response);

 end:
  riemann_client_free (client);

  return exit_status;
}
