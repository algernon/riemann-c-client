Using the riemann-c-client library
==================================

Before diving into the API of the library, let us have a short
overview of what to expect! The library provides both a lower-level
API and a higher-level API to interact with a [Riemann][riemann]
server. So what can we do with such a server?

 [Riemann]: http://riemann.io/

We can send [messages](#rcc_messages), which can contain
[events](#rcc_events), or a [query](#rcc_query). Queries will return
results, and if events are sent over TCP or TLS, they will return an
acknowledgement. So if sending events, one must handle the returned
data too, not just fire and forget the events. To make these clearer,
we'll start from the top down, and explore the high level helper
functions first.

Right after we learned how to connect and disconnect to and from a
server, of course! But even before that, we need to be able to use the
library. There are two headers one needs to care about:
`<riemann/riemann-client.h>`, which is the main entry point,
and includes every other header, except `<riemann/simple.h>`, which is
a set of optional helpers that make some of the most common use-cases
very simple, at the cost of memory or performance. One also needs to
link to the `riemann-client` library. With the use of `pkg-config`,
this all becomes trivial.

Table of contents
-----------------

* [Connecting to Riemann](#rcc-section-connecting-to-riemann)
  * [Connecting simply](#rcc-connecting-to-riemann-simply)
  * [Further client methods](#rcc-section-further-client-methods)
* [Sending events or doing queries, simply](#rcc-section-simple-events-and-queries)
* [Lower level APIs](#rcc-section-lower-level-apis)
  * [Messages](#rcc_messages)
  * [Events](#rcc_events)
  * [Attributes](#rcc_attributes)
  * [Queries](#rcc_query)
  * [Low-level client operations](#rcc_client)
* [Common conventions in the library](#rcc-section-common-conventions)
* [License](#rcc-section-license)

<a name="rcc-section-connecting-to-riemann"></a>
Connecting to Riemann
---------------------

The core function to connect to Riemann is
[`riemann_client_connect()`](#rcc_lib_riemann-client-connect), which
we will learn about a few paragraphs below. Among other things, it
needs a `riemann_client_t *` object, which we can create with
[`riemann_client_new()`](#rcc_lib_riemann-client-new). This
distinction between connecting to a server and creating an object is
useful when one wants to reuse an existing object, which in turn helps
with memory management, because one doesn't have to free the old
object, and allocate a new one. To match
[`riemann_clienct_connect()`](#rcc_lib_riemann-client-connect), there
is also
[`riemann_client_disconnect()`](#rcc_lib_riemann-client-disconnect),
which does the opposite. Simiarly,
[`riemann_client_free()`](#rcc_lib_riemann-client-free) can be used to
free up an object.

Lets see an example!

```c
#include <riemann/riemann-client.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int
main (void)
{
  riemann_client_t *client;
  int e;

  client = riemann_client_new ();
  if (!client)
    {
      fprintf (stderr, "Can't allocate client object: %s\n",
               strerror (errno));
      exit (1);
    }

  e = riemann_client_connect
    (client, RIEMANN_CLIENT_TLS,
     "localhost", 5555,
     RIEMANN_CLIENT_OPTION_TLS_CA_FILE, "ca.crt",
     RIEMANN_CLIENT_OPTION_TLS_CERT_FILE, "client.crt",
     RIEMANN_CLIENT_OPTION_TLS_KEY_FILE, "client.pem",
     RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT, 10000,
     RIEMANN_CLIENT_OPTION_NONE);
  if (e != 0)
    {
      fprintf (stderr, "Can't connect to Riemann: %s\n",
               strerror (-e));
      exit (1);
    }

  e = riemann_client_disconnect (client);
  if (e != 0)
    {
      fprintf (stderr, "Can't disconnect from Riemann: %s\n",
               strerror (-e));
      exit (1);
    }

  errno = 0;
  riemann_client_free (client);
  if (errno != 0)
    {
      fprintf (stderr, "Can't free client object: %s\n",
               strerror (errno));
      exit (1);
    }

  return 0;
}
```

This highlights a few things about the library, so lets dive in! The
library has a few
[common conventions](#rcc-section-common-conventions), to which all
functions adhere. We used a couple of functions in the example above,
lets see what they do!

<a name="rcc_lib_riemann-client-new"></a>
```c
riemann_client_t *riemann_client_new (void);
```

This is as simple as it gets: it creates a new, unconnected
`riemann_client_t *` object. In case of error, returns `NULL`, and
sets `errno` appropriately. The newly created object must be freed
with [`riemann_client_free()`](#rcc_lib_riemann-client-free), to avoid
memory leaks.

--------------------------------------------------------------

<a name="rcc_lib_riemann-client-free"></a>
```c
void riemann_client_free (riemann_client_t *client);
```

Disconnects from Riemann (via
[`riemann_client_disconnect()`](#rcc_lib_riemann-client-disconnect)),
and frees up any memory associated with the object. Sets errno on
failure, but doesn't touch it if the call succeeds. In most cases, it
is safe to ignore the error case here.

--------------------------------------------------------------

<a name="rcc_lib_riemann-client-connect"></a>
```c
int riemann_client_connect (riemann_client_t *client, riemann_client_type_t type,
                            const char *hostname, int port, ...);
```

To connect to Riemann, one must call `riemann_client_connect()` in one
way or the other, as this function does the dirty work of setting up a
connection. As usual, it either returns zero on success, or a negative
errno value on failure.

The parameters are a `riemann_client_t *` object, previously created,
followed by a client type, which can be any of `RIEMANN_CLIENT_TCP`,
`RIEMANN_CLIENT_UDP`, or `RIEMANN_CLIENT_TLS`. Be aware that if one
wants to do queries, `RIEMANN_CLIENT_UDP` cannot be used. If using
`RIEMANN_CLIENT_TCP` or `RIEMANN_CLIENT_TLS`, then sending events to
Riemann will also require one to read back the acknowledgements.

After these two, come the `hostname` and the `port`, which should be
self explanatory. There are no defaults, one cannot skip either
parameter, nor are there any `NULL` values that would imply a default
setting. The hostname is copied by the function, the caller is allowed
to free up the string later.

When using TLS, some extra parameters must be set, such as the
certificate authority, client certificate and client key file
paths. These are configurable by using the appropriate enum, followed
by the value. For non-TLS connections, everything after the port is
ignored. For TLS connections, the function expects a list of
option-value pairs, terminated by a value-less
`RIEMANN_CLIENT_OPTION_TLS_NONE` option. The rest of the options are:

* `RIEMANN_CLIENT_OPTION_TLS_CA_FILE`, followed by a string, that
  tells the library where to find the certificate authority file to
  use. The string is copied, and can be freed by the caller when
  appropriate.
* `RIEMANN_CLIENT_OPTION_TLS_CERT_FILE`, also followed by a string,
  that tells the library where to find the client certificate
  file. The string is copied, and can be freed by the caller when
  appropriate.
* `RIEMANN_CLIENT_OPTION_TLS_KEY_FILE`, also followed by a string,
  that tells the library where to find the client secret key file. The
  string is copied, and can be freed by the caller when appropriate.
* `RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT`, followed by an
  unsigned integer, the time - in milliseconds - to wait before timing
  out during a TLS handshake.
* `RIEMANN_CLIENT_OPTION_TLS_PRIORITIES`, followed by a string, representing the
  priority of cipher suites to be used for the session.

Once a new connection is established, the function will disconnect
from Riemann, if the client object is already connected. This
disconnect only happens after the new connection succeeded. Therefore,
it is safe to call `riemann_client_connect()` multiple times, without
calling
[`riemann_client_disconnect()`](#rcc_lib_riemann-client-disconnect)
inbetween.

--------------------------------------------------------------

<a name="rcc_lib_riemann-client-disconnect"></a>
```c
int riemann_client_disconnect (riemann_client_t *client)
```

As the name implies, disconnects a client object from Riemann, but
does not free the object: that is done by
[`riemann_client_free()`](#rcc_lib_riemann-client-free). On success,
returns zero as usual, and a negative errno value on failure. It is
worth checking the return value, because the client may already be in
a half-disconnected state (due, for example, to network failure),
which one may want to pay attention to.

After calling the function, the client object can be used again to
connect to Riemann. However, if one does not wish to reuse the object,
it is more succinct to call
[`riemann_client_free()`](#rcc_lib_riemann-client-free) instead, which
will also disconnect the client, and free up resources in one step.

<a name="rcc-connecting-to-riemann-simply"></a>
### Connecting simply

In a lot of cases, creating a new client object is followed by
connecting to Riemann. This is a pattern used so often that the
library provides a way to do both things in one step:

<a name="rcc_lib_riemann-client-create"></a>
```c
riemann_client_t *riemann_client_create (riemann_client_type_t type,
                                         const char *hostname, int port,
                                         ...);
```

As mentioned above, this is a combination of
[`riemann_client_new()`](#rcc_lib_riemann-client-new) and
[`riemann_client_connect`](#rcc_lib_riemann-client-connect). As such,
it takes the exact same parameters as `riemann_client_connect()`, sans
the client object itself, and behaves the same way too.

<a name="rcc-section-further-client-methods"></a>
### Further client methods

There are two other methods related to client objects that need
special mention here:

<a name="rcc_lib_riemann-client-get-fd"></a>
```c
int riemann_client_get_fd (riemann_client_t *client);
```

Given a connected client, returns the file descriptor used. One can
use this file descriptor to set socket options that the library
doesn't set, or use it for an event library, and so on.

In case the client is not connected, the function returns `-1`. If the
parameter is `NULL`, it will return `-EINVAL`.

--------------------------------------------------------------

<a name="rcc_lib_riemann-client-set-timeout"></a>
```c
int riemann_client_set_timeout (riemann_client_t *client,
                                struct timeval *timeout);
```

Analogous to the `RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT` option
for TLS connections, this one works for all kinds of clients, but
affects not only the TLS handshake, but all blocking operations. If
any operation takes longer than the specified interval, it will time
out and eventually return an error.

One can use this function in case where locking up indefinitely is not
an acceptable behaviour. By default, there is no timeout.

<a name="rcc-section-simple-events-and-queries"></a>
Sending events or doing queries, simply
---------------------------------------

The most straightforward way to send an event using the library is
using the
[`riemann_communicate_event`](#rcc_lib_riemann-communicate-event)
function. Similarly, to do a query, there's
[`riemann_communicate_query`](#rcc_lib_riemann-communicate-query). Both
of these functions will require a connected client, but will construct
the event object to send, or the object to perform the query with
on the fly, and free intermediate objects too.

The upside of these functions is that they set up intermediate objects
automatically, and also wait for the response from Riemann, in one
large step.

The downside is that you can't iteratively construct the event - or
the query - with as much freedom as with lower level functions (we'll
touch those later). Furthermore, while Riemann supports multiple
events within a single message, the
[`riemann_communicate_event`](#rcc_lib_riemann-communicate-event)
function can only send a single event at a time.

It is highly discouraged to mix these simplified APIs with the lower
level ones! That can lead to a lot of confusion. For example, sending
an event, without reading the acknowledgement back, then using
`riemann_communicate_event()` to send another event will return the
acknowledgement of the previously sent event. Don't do that. When
using these APIs, use these exclusively, or if mixing, always make
sure that writes and reads happen in the required order.

These functions are not part of the standard set of functions
available when including `<riemann/riemann-client.h>`, one has to
include `<riemann/simple.h>` in addition too. Lets look at the
functions in detail, then!

<a name="rcc_lib_riemann-communicate-event"></a>
```c
riemann_message_t *riemann_communicate_event (riemann_client_t *client, ...);
```

The function takes a connected client object, followed by a set of
field-value pairs, terminated by `RIEMANN_EVENT_FIELD_NONE`. The
allowed fields and their values are listed below. We'll see an example
that demonstrates the use of each field a few paragraphs down. The
library supports all fields that the Riemann protocol has support for.

* `RIEMANN_EVENT_FIELD_TIME`: The `time` field, a 64-bit signed
  integer (`int64_t`). Be aware that when using variadic arguments
  with directly specified values, the compiler does not know what kind
  of integer type to cast - say - `300` to. So one either has to cast
  it to `int64_t` by hand, or use a typed variable instead.
* `RIEMANN_EVENT_FIELD_TIME_MICROS`: Since version 0.2.13, Riemann
  supports microseconds resolution for events. The `time_micros`
  field, a 64-bit signed integer (`int64_t`), is the time in unix
  epoch microseconds. Be aware that when using variadic arguments with
  directly specified values, the compiler does not know what kind of
  integer type to cast - say - `300` to. So one either has to cast it
  to `int64_t` by hand, or use a typed variable instead.
* `RIEMANN_EVENT_FIELD_STATE`: The `state` field, a `NULL`-terminated
  string. The string is copied, and the caller is allowed to free the
  passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_SERVICE`: The `service` field, a
  `NULL`-terminated string. The string is copied, and the caller is
  allowed to free the passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_HOST`: The `host` field, a `NULL`-terminated
  string. The string is copied, and the caller is allowed to free the
  passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_DESCRIPTION`: The `description` field, a
  `NULL`-terminated string. The string is copied, and the caller is
  allowed to free the passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_TAGS`: A list of `NULL`-terminated strings. The
  list itself is terminated by a `NULL`. Each element will be a
  separate tag attached to the event. Similarly to other string
  values, the values are copied, and the caller is free to destroy the
  strings anytime after the function finished.
* `RIEMANN_EVENT_FIELD_TTL`: The `ttl` field, a `float` value. One has
  to make sure that one either passes a float-typed variable, or if
  using a value directly, then one has to use something that the
  compiler will recognise as float, or explicitly cast it to that
  type.
* `RIEMANN_EVENT_FIELD_METRIC_S64`, `RIEMANN_EVENT_FIELD_METRIC_D`,
  and `RIEMANN_EVENT_FIELD_METRIC_F`: The `metric` field, as either a
  signed 64-bit integer, a double, or a float typed number,
  respectively. As with the rest of the numeric values, one has to pay
  attention to proper typing. While it is allowed by the library to
  specify more than one of these three fields, doing so is not
  recommended: use only one, the most appropriate type for the metric
  at hand.
* `RIEMANN_EVENT_FIELD_ATTRIBUTES`: A `NULL`-terminated list of
  [`riemann_attribute_t`](#rcc-attributes) objects, to be used as
  custom, named attributes of the event. This field type is rarely
  used with `riemann_communicate_event`, and
  `RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES` are recommended instead. The
  list is borrowed, the caller should not touch them in any way
  afterwards.
* `RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES`: A list of name-value pairs,
  terminated by a `NULL` key. Each name-value pair is a pair of
  `NULL`-terminated strings, both of which are copied, and the caller
  is allowed to destroy them whenever it sees fit.

To make this all a bit clearer, lets see an example event! We'll
discuss the returned message object after the demo.

```c
#include <riemann/riemann-client.h>
#include <riemann/simple.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

int
main (void)
{
  riemann_client_t *client;
  riemann_message_t *response;

  client = riemann_client_create(RIEMANN_CLIENT_TCP,
                                 "localhost", 5555);
  response = riemann_communicate_event(
    RIEMANN_EVENT_FIELD_TIME, (int64_t) 1440506158000,
    RIEMANN_EVENT_FIELD_STATE, "ok",
    RIEMANN_EVENT_FIELD_SERVICE, "riemann-c-client/api-docs/communicate-event",
    RIEMANN_EVENT_FIELD_HOST, "localhost",
    RIEMANN_EVENT_FIELD_DESCRIPTION, "A sample event",
    RIEMANN_EVENT_FIELD_TAGS, "tag-1", "tag-2", NULL,
    RIEMANN_EVENT_FIELD_TTL, (float) 360,
    RIEMANN_EVENT_FIELD_METRIC_S64, (int64_t) 42,
    RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
      "custom-attribute", "custom-value",
      "another-attribute", "some other value",
      NULL,
    RIEMANN_EVENT_FIELD_NONE
  );

  if (!response)
    {
      fprintf (stderr, "Error communicating with Riemann: %s\n",
               strerror (errno));
      exit (1);
    }

  if (response->error)
    {
      fprintf (stderr, "Error communicating with Riemann: %s\n",
               response->error);
      exit (1);
    }

  if (response->has_ok && !response->ok)
    {
      fprintf (stderr, "Error communicating with Riemann: %s\n",
               strerror (errno));
      exit (1);
    }

  riemann_message_free (response);
  riemann_client_free (client);

  return 0;
}
```

If the communication fails for whatever reason, the function can
return `NULL` (for example when creating the event failed), and then
it sets errno appropriately. It can also fail on the server side, but
get a response back, in which case `response->error` will be
set. It can also fail when the `ok` field is false: when
`response->has_ok` is set, but `response->ok` is not. In the vast
majority of situations, the `ok` field will be set to false, and an
error will be set too.

If everything succeeds, we get a [`riemann_message_t`](#rcc_messages)
object back. On this object, only the `has_ok`, `ok` and `error`
fields are appropriate. Any other field should be ignored. The
returned message object needs to be freed by the caller by calling
[`riemann_message_free()`](#rcc_lib_riemann-message-free).

--------------------------------------------------------------

<a name="rcc_lib_riemann-communicate-query"></a>
```c
riemann_message_t *riemann_communicate_query (riemann_client_t *client,
                                              const char *query_string);
```

When wanting to perform a query, without having to care about
intermediate objects, when object reuse is not useful, this is the
function one wants to use. Given a connected client object, and a
query string in the riemann query language, it will send the request,
and wait for a response.

If the query fails for some reason or the other, the function can
return NULL, or a [`riemann_message_t`](#rcc_messages) object with the
`has_ok` field set, and `ok` set to zero (and/or the `error` field
set). In the vast majority of cases, in case of failure, the function
will either return `NULL` and set `errno`, or return an object with
`has_ok` present, `ok` set to false, and `error` also set to a
non-`NULL` value.

In case of success, the returned [`riemann_message_t`](#rcc_messages)
will have `has_ok` and `ok` set to a non-zero value. The `n_events`
property will tell the number of results (which can be zero!), and
`events` will be an array of [`riemann_event_t`](#rcc_events)
objects. The array will contain exactly the same number of events as
`n_events` described.

The function does not work when the client is connected on UDP, and
will always return an error in that case.

<a name="rcc-section-lower-level-apis"></a>
Lower level APIs
-----------------

Now that we have a reasonable idea about the library, and learned how
to send events and perform queries, it is time to look at the lower
levels of the API, so we can architect our applications in a way that
takes advantage of some advanced features, such as sending events in
bulk, and reusing objects to save on allocator load.

<a name="rcc_messages"></a>
### Messages

Messages (`riemann_message_t`) are the high-level container objects in
Riemann, and in turn, in the library too. They wrap around event
lists, queries and server responses: they are used all over the
place. The object is not opaque, its fields are defined by the Riemann
protobuf spec. The fields that are relevant for this library are:

* `->has_ok` and `->ok`: Only relevant for responses. If `->has_ok` is
  set to a non-zero value, then `->ok` boolean field determines
  whether the operation the server responded to was successful or not.
* `->error`: Only relevant for responses too. In case there's a
  textual error message, it will be available under this field.
* `->query`: Only relevant when performing a query. One can't mix
  queries and event sending. The value is a
  [`riemann_query_t`](#rcc_query) object.
* `->n_events` and `->events`: Relevant for responses (in which case
  these are set by the library), and for sending events to Riemann (in
  which case these must be set up by the application, via API calls to
  the library).

The [simplified API](#rcc-section-simple-events-and-queries)
constructs these under the hood. When one wants more flexibility and
stricter control over their objects, the library provides a number of
functions that make it easier to work with messages:


#### Creating & freeing messages

Creating and freeing messages is a lot less involved than dealing with
client objects. For a number of reasons, reusing message objects is
not all that common. One such reason is that resetting a message
object is fairly costly, to throwing away the old, and allocating a
new one is a negligible difference in performance and resource use.

<a name="rcc_lib_riemann-message-new"></a>
```c
riemann_message_t *riemann_message_new (void);
```

As the name implies, allocates a new message object, and returns
it. If the allocation fails for some reason, returns NULL.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-free"></a>
```c
void riemann_message_free (riemann_message_t *message);
```

Frees up the resources allocated to a message object. Any
[queries](#rcc_query) or [events](#rcc_events) associated with the
message will also be freed. If one wishes to reuse those objects, one
has to make a copy of them first (by cloning them, for example).

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-create-with-events"></a>
```c
riemann_message_t *riemann_message_create_with_events (riemann_event_t *event, ...);
riemann_message_t *riemann_message_create_with_events_va (riemann_event_t *event, va_list aq);
```

A shortcut for allocating a message and setting events via
[`riemann_message_set_events()`](#rcc_lib_riemann-message-set-events). Returns
the newly allocated message, or `NULL` on error, in which case `errno`
will also be set appropriately.

The function comes in two variants: one that takes a list of
[`riemann_event_t`](#rcc_events) objects, terminated by a `NULL`
object; and another that takes an event, and a `va_list`. The latter
is primarily meant for libraries that wrap this library for another
language.

In both cases, the arguments are the events, and the event objects
will be borrowed, the caller must not touch them afterwards. If this
is not desired, a copy should be made prior to calling this function.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-create-with-query"></a>
```c
riemann_message_t *riemann_message_create_with_query (riemann_query_t *query);
```

A shortcut for allocating a message and setting the query via
[`riemann_message_set_query()`](#rcc_lib_riemann-message-set-query). Returns
the newly allocated message, or `NULL` on error, in which case `errno`
will also be set appropriately.

The query object will be borrowed, and the caller must not touch them
afterwards. If this is not desired, a copy should be made prior to
calling this function.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-clone"></a>
```c
riemann_message_t *riemann_message_clone (const riemann_message_t *message);
```

Creates a deep copy of the message, and returns it. Any events,
queries or errors within the message will be cloned too.

In case of failure, returns `NULL` and sets `errno` to an appropriate
value.

#### Manipulating message contents

<a name="rcc_lib_riemann-message-set-events"></a>
```c
int riemann_message_set_events (riemann_message_t *message, ...);
int riemann_message_set_events_va (riemann_message_t *message, va_list aq);
int riemann_message_set_events_n (riemann_message_t *message,
                                  size_t n_events,
                                  riemann_event_t **events);
```

Setting the events in a message can be done in three forms. Which to
use, depends largely on the situation. All three functions do the same
thing - with slightly different syntax: free up any previous events
associated with the message, and use the new set of events specified
by the caller. The events passed as arguments will be borrowed, and
the caller should not touch them anymore. If that is not desired, a
copy should be made prior to calling these functions.

All forms return zero on success, a negative `errno` value on failure.

The first form, `riemann_message_set_events()` takes a message object,
and a `NULL`-terminated list of [events](#rcc_events). This is most
useful when the number of events are known at compile time.

The second form, `riemann_message_set_events_va()` takes a message
object, and a varargs list of [events](#rcc_events). The list should
still be `NULL`-terminated, but wrapped in a `va_list`. This is most
useful for language bindings.

The last form, `riemann_message_set_events_n()` is likely the most
used form, as it does not require `NULL`-terminating the list of
events, and allows one to specify the events in an array, and give the
size of the array as a separate argument. This form is expected to be
used when building up a message iteratively, where the number of
events are only known at run time.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-append-events"></a>
```c
int riemann_message_append_events (riemann_message_t *message, ...);
int riemann_message_append_events_va (riemann_message_t *message, va_list aq);
int riemann_message_append_events_n (riemann_message_t *message,
                                     size_t n_events,
                                     riemann_event_t **events);
```

Similarly to the
[`riemann_message_set_events`](#rcc_lib_riemann-message-set-events)
family of functions, the library supports appending events too. These
functions come in three forms too, and work the same way as the set
functions, except events previously added to the message will remain
there, and the new ones will be added to the list, instead of
replacing the old set.

--------------------------------------------------------------


<a name="rcc_lib_riemann-message-set-query"></a>
```c
int riemann_message_set_query (riemann_message_t *message,
                               riemann_query_t *query);
```

Messages can contain a [query](#rcc_query) too, not only events. It
can only contain one of the two, even if the library permits setting
both.

With this function, one can set the query contained in the
message. Any previously set queries will be freed up, and the new one
will be borrowed, the caller must not touch it afterwards.

The function returns zero on success, a negative `errno` value on
failure.

#### Serialisation & deserialisation

Messages are the structure we talk to Riemann with, and as such, they
can be serialised and deserialised. On the wire, each message is
prefixed with a 32-bit length header, followed by the serialised
message itself.

<a name="rcc_lib_riemann-message-to-buffer"></a>
```c
uint8_t *riemann_message_to_buffer (riemann_message_t *message, size_t *len);
```

Takes a message object, and serialises it. Returns the byte buffer
in the on-the-wire format (prefixed with the length). Also returns the
length in the `len` output variable (unless it is NULL).

On failure, returns `NULL`, and sets up `errno` appropriately.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-from-buffer"></a>
```c
riemann_message_t *riemann_message_from_buffer (uint8_t *buffer, size_t len);
```

Deserialises a header-less byte-buffer into a message object. It does
not work with the on-the-wire format, the length header must be
stripped first, and passed as the second argument.

Returns a newly allocated message object on success, `NULL` on
failure, in which case it also sets `errno`.

--------------------------------------------------------------

<a name="rcc_lib_riemann-message-get-packed-size"></a>
```c
size_t riemann_message_get_packed_size (riemann_message_t *message);
```

When programmatically building up a message, it is often useful to
know the size of the serialised form, so one wouldn't grow a message
indefinitely, but cut off after a certain size, and start a new one.

Serialising and checking the length would be very costy, so this
function exists to check the size of the message, without having to
serialize it.

Returns the size of the message, or 0 on failure, in which case it
also sets `errno`.

<a name="rcc_events"></a>
### Events

Events are at the core of Riemann. One sends events to it, and when
one launches queries, gets a list of matching events back. The library
provides a number of functions to work with events, we'll see them
just down below.

But before that, lets have a look at the fields our event objects
have! They match what the Riemann protocol buffer specification
declares, but we include them here for the sake of completeness.

#### Event fields

* `->has_time` and `->time`: The timestamp, and a boolean flag that
  signals whether the timestamp is part of the event.
* `->has_time_micros` and `->time_micros`: The timestamp in
  microseconds, and a boolean flag that signals whether the timestamp
  is part of the event.
* `->state`: The event state, a `NULL`-terminated string.
* `->service`: The service name, a `NULL`-terminated string.
* `->host`: The host the event originates from, a `NULL`-terminated
  string.
* `->description`: The event description, a `NULL`-terminated string.
* `->n_tags` and `->tags`: The number of tags attached to the event,
  and an array of `NULL`-terminated strings, the tags themselves.
* `->has_ttl` and `->ttl`: A flag indicating whether the TTL field is
  present, and the float field itself.
* `->n_attributes` and `->attributes`: The number of custom attributes
  attached to the event, and an array of
  [attributes](#rcc_attributes).
* `->has_metric_sint64`, `->metric_sint64`, `->has_metric_d`,
  `->metric_d`, `->has_metric_f`, and `->metric_f`: The metric field,
  in signed 64-bit integer, double or float representation, along with
  boolean fields that signal the presence of a particular format.

#### Creating & freeing events

<a name="rcc_lib_riemann-event-new"></a>
```c
riemann_event_t *riemann_event_new (void);
```

Allocates a new, empty event. Returns the new event on success, `NULL`
otherwise, in which case it sets up `errno` too.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-create"></a>
```c
riemann_event_t *riemann_event_create (...);
riemann_event_t *riemann_event_create_va (riemann_event_field_t field, va_list aq);
```

This function takes a list of field-value pairs, and creates a new
event. In case of failure, returns `NULL` and sets `errno` to the
appropriate value. The field list must be terminated with a
`RIEMANN_EVENT_FIELD_NONE` field - everything and anything after that
will be ignored. See
[`riemann_event_set()`](#rcc_lib_riemann-event-set) for a list of
allowed fields and their expected values.

The second form, `riemann_event_create_va()` works similarly, but
takes a `va_list` instead, and is meant for language bindings
primarily.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-clone"></a>
```c
riemann_event_t *riemann_event_clone (const riemann_event_t *event);
```

Would one wish to make a copy of an event already created, this
function does just that. Returns a newly allocated event object, or
`NULL` on failure, in which case it sets up `errno` as well.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-free"></a>
```c
void riemann_event_free (riemann_event_t *event);
```

Frees up all resources associated with the event, including any
embedded attributes. On failure, sets `errno`, but otherwise doesn't
touch it.

#### Setting and updating event contents

<a name="rcc_lib_riemann-event-set"></a>
```c
int riemann_event_set (riemann_event_t *event, ...);
int riemann_event_set_va (riemann_event_t *event,
                          va_list aq);
```

Events are only useful if they have at least some of their fields
set. These functions help one do just that. If one tries to set the
same field twice, the old value will be freed up, and replaced by the
new one. Both functions return zero on success, or a negative `errno`
value in case of failure. Setting fields are not atomic, therefore in
case of an error, the event may well be in an inconsistent state.

Both functions take an event, and a list of field-value pairs,
terminated by `RIEMANN_EVENT_FIELD_NONE`. The allowed fields and their
values are listed below:

* `RIEMANN_EVENT_FIELD_TIME`: The `time` field, a 64-bit signed
  integer (`int64_t`). Be aware that when using variadic arguments
  with directly specified values, the compiler does not know what kind
  of integer type to cast - say - `300` to. So one either has to cast
  it to `int64_t` by hand, or use a typed variable instead.
* `RIEMANN_EVENT_FIELD_TIME_MICROS`: Since version 0.2.13, Riemann
  supports microseconds resolution for events. The `time_micros`
  field, a 64-bit signed integer (`int64_t`), is the time in unix
  epoch microseconds. Be aware that when using variadic arguments with
  directly specified values, the compiler does not know what kind of
  integer type to cast - say - `300` to. So one either has to cast it
  to `int64_t` by hand, or use a typed variable instead.
* `RIEMANN_EVENT_FIELD_STATE`: The `state` field, a `NULL`-terminated
  string. The string is copied, and the caller is allowed to free the
  passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_SERVICE`: The `service` field, a
  `NULL`-terminated string. The string is copied, and the caller is
  allowed to free the passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_HOST`: The `host` field, a `NULL`-terminated
  string. The string is copied, and the caller is allowed to free the
  passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_DESCRIPTION`: The `description` field, a
  `NULL`-terminated string. The string is copied, and the caller is
  allowed to free the passed variable anytime, if it is necessary.
* `RIEMANN_EVENT_FIELD_TAGS`: A list of `NULL`-terminated strings. The
  list itself is terminated by a `NULL`. Each element will be a
  separate tag attached to the event. Similarly to other string
  values, the values are copied, and the caller is free to destroy the
  strings anytime after the function finished.
* `RIEMANN_EVENT_FIELD_TTL`: The `ttl` field, a `float` value. One has
  to make sure that one either passes a float-typed variable, or if
  using a value directly, then one has to use something that the
  compiler will recognise as float, or explicitly cast it to that
  type.
* `RIEMANN_EVENT_FIELD_METRIC_S64`, `RIEMANN_EVENT_FIELD_METRIC_D`,
  and `RIEMANN_EVENT_FIELD_METRIC_F`: The `metric` field, as either a
  signed 64-bit integer, a double, or a float typed number,
  respectively. As with the rest of the numeric values, one has to pay
  attention to proper typing. While it is allowed by the library to
  specify more than one of these three fields, doing so is not
  recommended: use only one, the most appropriate type for the metric
  at hand.
* `RIEMANN_EVENT_FIELD_ATTRIBUTES`: A `NULL`-terminated list of
  [`riemann_attribute_t`](#rcc-attributes) objects, to be used as
  custom, named attributes of the event. This field type is rarely
  used with `riemann_communicate_event`, and
  `RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES` are recommended instead. The
  list is borrowed, the caller should not touch them in any way
  afterwards.
* `RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES`: A list of name-value pairs,
  terminated by a `NULL` key. Each name-value pair is a pair of
  `NULL`-terminated strings, both of which are copied, and the caller
  is allowed to destroy them whenever it sees fit.

The second form takes a `va_list`, and is intended for language
bindings primarily.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-set-one"></a>
```c
int riemann_event_set_one (riemann_event_t *event,
                           riemann_event_field_t field, ...);
```

When programmatically building up an event, a common case is when one
only changes a since field at a time. Having to terminate the list
with `RIEMANN_EVENT_FIELD_NONE` all the time would be overly verbose,
so a short macro exists that makes this simpler.

This function takes an event, a single field (**without** the
`RIEMANN_EVENT_FIELD_` prefix!), and a value. Behaves the same as
[`riemann_event_set()`](#rcc_lib_riemann-event-set) otherwise.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-tag-add"></a>
```c
int riemann_event_tag_add (riemann_event_t *event, const char *tag);
```

Building events up iteratively, one may find oneself in the situation
where one wants to add tags in separate steps. The
[`riemann_event_set`](#rcc_lib_riemann-event-set) function would
replace the full tag list, which is not desirable in this case.

This function appends a new tag to the event's existing tag
list. Returns zero on success, or a negative `errno` value on failure.

--------------------------------------------------------------

<a name="rcc_lib_riemann-event-attribute-add"></a>
```c
int riemann_event_attribute_add (riemann_event_t *event,
                                 riemann_attribute_t *attrib);
int riemann_event_string_attribute_add (riemann_event_t *event,
                                        const char *key,
                                        const char *value);
```

Similar to [tags](#rcc_lib_riemann-event-tag-add), one may want to
attach attributes in separate steps too. These two functions help with
that. Both return zero on success, or a negative `errno` value on
failure.

The first form expects an [attribute object](#rcc_attributes), the
second one expects a key and a value, and constructs the attribute
object behind the scenes.

The first form is best used when one wants to - and can - reuse
attribute objects. When one has a pre-defined set of attributes, the
first form may be more efficient. For all other cases, the second form
is much more succint and convenient.

<a name="rcc_attributes"></a>
### Attributes

Attributes are custom key-value pairs one can attach to an
event. They are rarely reused, and thus, using helpers like
[`riemann_event_string_attribute_add`](#rcc_lib_riemann-event-attribute-add)
or the `RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES` pseudo-field is
recommended instead.

Sometimes, however, one needs to deal with attribute objects directly,
and therefore, we have a look at them too!

#### Creating & freeing attributes

<a name="rcc_lib_riemann-attribute-new"></a>
```c
riemann_attribute_t *riemann_attribute_new (void);
```

The easiest way to create an attribute object is this function. It
simply returns the newly created, empty attribute. In case of an
error, returns `NULL` and sets `errno` to an appropriate value.

--------------------------------------------------------------

<a name="rcc_lib_riemann-attribute-create"></a>
```c
riemann_attribute_t *riemann_attribute_create (const char *key,
                                               const char *value);
```

Creating an empty attribute is rarely useful, therefore there is a
shortcut to create a new one, with both key and value pre-set. As
expected, returns a newly allocated attribute object on success, and
`NULL` on failure, in which case it also sets up `errno`.

--------------------------------------------------------------

<a name="rcc_lib_riemann-attribute-clone"></a>
```c
riemann_attribute_t *riemann_attribute_clone (const riemann_attribute_t *attrib);
```

Attaching an attribute to an event embeds the attribute object. Would
one want to reuse it, a clone has to be made first, with this
function.

Returns a cloned object, or `NULL` on failure, in which case it also
sets up `errno`.

--------------------------------------------------------------

<a name="rcc_lib_riemann-attribute-free"></a>
```c
void riemann_attribute_free (riemann_attribute_t *attrib);
```

Frees up the attribute object. If any of the operations fail, sets
`errno`, but otherwise it won't touch it.

#### Manipulating attributes

<a name="rcc_lib_riemann-attribute-set"></a>
```c
int riemann_attribute_set_key (riemann_attribute_t *attrib, const char *key);
int riemann_attribute_set_value (riemann_attribute_t *attrib, const char *value);
int riemann_attribute_set (riemann_attribute_t *attrib,
                           const char *key, const char *value);

```

To change the key, the value, or both properties of an attribute,
these functions help. They all return zero on success, and a negative
`errno` value on failure.

<a name="rcc_query"></a>
### Queries

To query riemann, one will have to wrap `riemann_query_t` objects into
a [`riemann_message_t`](#rcc_messages) object. But to do that, one has
to be able to construct query objects first.

A query object has a single field: `->string`, which is the query
string in the Riemann query language syntax. The library provides no
helpers and API to construct such a string.

#### Creating and freeing query objects

<a name="rcc_lib_riemann-query-new"></a>
```c
riemann_query_t *riemann_query_new (const char *string);
```

Creates a new query object. Since a query object has a single
property, the query string, this function requires an
argument. However, the supplied string can be NULL, in which case the
function will still allocate the object, but won't set the property.

Returns a newly allocated object, or `NULL` on failure, in which case
it also sets `errno` to an appropriate value.

--------------------------------------------------------------

<a name="rcc_lib_riemann-query-clone"></a>
```c
riemann_query_t *riemann_query_clone (const riemann_query_t *query);
```

Because query objects get borrowed by the message object when binding
the two together, if one wants to reuse query objects, one has to
clone it first.

This function returns the cloned query object, or `NULL` on failure,
in which case it also sets up `errno`.

--------------------------------------------------------------

<a name="rcc_lib_riemann-query-free"></a>
```c
void riemann_query_free (riemann_query_t *query);
```

Frees up all resources allocated to the query object. In case of
failure, sets `errno` to an appropriate value, but otherwise does not
touch it.

#### Manipulating query objects

<a name="rcc_lib_riemann-query-set-string"></a>
```c
int riemann_query_set_string (riemann_query_t *query, const char *string);
```

To change the query string of a query object, one can use this
function. It frees up any previous query strings previously associated
with the query object, before assigning the new one.

Returns zero on success, a negative `errno` value otherwise.

<a name="rcc_client"></a>
### Low-level client operations

We already learned how to send one-off operations to Riemann using the
[simplified API](#rcc-section-simple-events-and-queries). But for a
lot of use cases, the simplified API is inadequate. We will now learn
about the functions that make us able to do a few things more
efficiently, using a lower-level API. We'll trade simplicity for
performance, and will see how to tie the [message](#rcc_messages),
[event](#rcc_events) and [query](#rcc_query) APIs together with the
communication functions.

#### Sending and receiving messages

<a name="rcc_lib_riemann-client-send-message"></a>
```c
int riemann_client_send_message (riemann_client_t *client,
                                 riemann_message_t *message);
int riemann_client_send_message_oneshot (riemann_client_t *client,
                                         riemann_message_t *message);
```

To send a message, one constructed at run time, and not at compile
time like in case of the
[simplified API](#rcc-section-simple-events-and-queries), these
functions shall be used. They take a client and a message object, and
send the message over the wire. Both functions handle serialisation
themselves, and both return zero on success, and a negative `errno`
value on failure.

The second function, `riemann_client_send_message_oneshot()` will also
free the message before returning. Be aware that the message will be
freed even if the send did not succeed!

--------------------------------------------------------------

<a name="rcc_lib_riemann-send"></a>
```c
int riemann_send (riemann_client_t *client,
                  riemann_event_field_t field, ...);
int riemann_send_va (riemann_client_t *client,
                     riemann_event_field_t field, va_list aq);
```

Part of the simplified API, thus requires `#include
<riemann/simple.h>`.

Allows one to send a compile-time constructed event to Riemann,
without having to care about intermediate objects. These functions
create the event, and the message it is embedded in automatically. As
such, neither event, nor message can be reused, and it only supports
sending a single event at a time.

Both functions take a client, and a
`RIEMANN_EVENT_FIELD_NONE`-terminated list of field-value pairs. See
[`riemann_event_set()`] for a list of supported fields and their
values. They both return zero on success, and a negative `errno` value
on failure.

Unlike the
[`riemann_communicate_event`](#rcc_lib_riemann-communicate-event)
function, these deal only with the sending part. They will not wait
for a reply, that becomes the responsibility of the programmer. See
[`riemann_client_recv_message()`](#rcc_lib_riemann-client-recv-message)
for more information about receiving replies.

--------------------------------------------------------------

<a name="rcc_lib_riemann-query"></a>
```c
riemann_message_t *riemann_query (riemann_client_t *client,
                                  const char *query);
```

Part of the simplified API, thus requires `#include
<riemann/simple.h>`.

Performs a query against Riemann, and returns the results wrapped in a
[message](#rcc_messages) object. In case of failure, returns `NULL`
and sets `errno` to an appropriate value.

--------------------------------------------------------------

<a name="rcc_lib_riemann-client-recv-message"></a>
```c
riemann_message_t *riemann_client_recv_message (riemann_client_t *client);
```

Reads a reply from Riemann, and deserialises it into a
[message](#rcc_messages) object. Returns a newly allocated object, or
`NULL` on failure, in which case it also sets `errno` to an
appropriate value.

--------------------------------------------------------------

<a name="rcc_lib_riemann-communicate"></a>
```c
riemann_message_t *riemann_communicate (riemann_client_t *client,
                                        riemann_message_t *message);
```

Part of the simplified API, thus requires `#include
<riemann/simple.h>`.

Allows one to send a message, wait for, and read a reply in one
step. The message object will be freed before the function returns.

Returns the server's reply deserialised into a
[message](#rcc_messages) object, or `NULL` on failure, in which case
it also sets `errno` to an appropriate value.

#### Bringing it all together

```c
#include <riemann/riemann-client.h>
#include <riemann/simple.h>
#include <stdio.h>

/* Error handling is deliberately missing from this example, to make
   it shorter. In a real program, don't do this. */

int
main (void)
{
  riemann_client_t *client;
  riemann_message_t *event_message, *query_message, *response;
  riemann_event_t *event;
  riemann_query_t *query;
  riemann_attribute_t *attr;

  client = riemann_client_create (RIEMANN_CLIENT_TCP, "localhost", 5555);
  event = riemann_event_create
    (RIEMANN_EVENT_FIELD_SERVICE, "riemann-c-client/demo",
     RIEMANN_EVENT_FIELD_HOST, "localhost",
     RIEMANN_EVENT_FIELD_STATE, "ok",
     RIEMANN_EVENT_FIELD_TAGS, "riemann-c-client", "demo", NULL,
     RIEMANN_EVENT_FIELD_STRING_ATTRIBUTES,
       "x-client", "riemann-c-client",
       NULL,
     RIEMANN_EVENT_FIELD_NONE);
  attr = riemann_attribute_create ("x-attribute", "some value");

  riemann_event_tag_add (event, "a-third-tag");
  riemann_event_attribute_add (event, attr);
  riemann_event_string_attribute_add (event, "x-string-key", "some value");

  event_message = riemann_message_create_with_events (event, NULL);

  response = riemann_communicate (client, event_message);

  printf ("response->ok: %d\n", response->ok);

  riemann_message_free (response);

  query = riemann_query_new ("service = \"riemann-c-client/demo\"");
  query_message = riemann_message_create_with_query (query);

  riemann_client_send_message_oneshot (client, query_message);
  response = riemann_client_recv_message (client);

  printf ("response->n_events: %zu\n", response->n_events);

  riemann_message_free (response);

  riemann_client_free (client);

  return 0;
}
```

This little application connects to a Riemann server running on
localhost, at the default port. Then it creates an event with some
fields pre-set, then it creates an attribute. It continues after that
by attaching a tag, the created attribute object, and another
attribute to the event, before wrapping it in a message.

Then it uses [`riemann_communicate`](#rcc_lib_riemann-communicate) to
both send the message, and await a reply.

Once it's done with that, it constructs a query, and send it in one
step, and reads back the results in another one.

That's all, so simple. A bit verbose, perhaps, but straightforward
nevertheless. The example application within the source tree may be of
interest for anyone wishing to study how to use the library.

<a name="rcc-section-common-conventions"></a>
Common conventions in the library
---------------------------------

### Return values and error reporting

The library has three types of functions: those that return an int,
those that return an object, and void functions.

Functions that return an int will usually return a negative `errno`
value on failure (unless a negative number makes sense, in which case
they will report errors in some other way, and documentation will tell
how).

Functions that return an object will return `NULL` on failure, and set
`errno` appropriately. Some functions can report server-side failures,
in which case the error will be wrapped in the appropriate object. But
these functions return `NULL` nevertheless.

Functions that have no return value will set `errno` upon failure. The
error case of these functions can usually be safely ignored.

### Argument copying & borrowing

Many functions in the library accept various pointers. The general
rule of thumb used within the library is that pointers to primitive
types are copied by value, and the caller remains in control of the
original pointer. For example, strings will be duplicated when and
where necessary. Exceptions are documented at the relevant functions,
if any.

For types defined by the library, however, the pointers are usually
borrowed, and the caller must avoid touching them, or relying on them
in any way, as the library will be in control of them from that point
onward. Exceptions are, of course, documented at the relevant
functions.

<a name="rcc-section-license"></a>
License
-------

Copyright (C) 2013-2017 Gergely Nagy, released under the terms
of the [GNU Lesser General Public License][lgpl], version 3+.

 [lgpl]: http://www.gnu.org/licenses/lgpl.html
