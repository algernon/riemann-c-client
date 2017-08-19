riemann-c-client 1.10.2
=======================
Released on 2017-08-19

Bugfixes
--------

* A number of formatting issues in the API docs have been fixed.

riemann-c-client 1.10.1
=======================
Released on 2017-06-12

Bugfixes
--------

* The library compiles on OSX/Darwin again, after fixing a symbol aliasing issue.

  Reported by @ilovezfs.

riemann-c-client 1.10.0
=======================
Released on 2017-06-09

Features
--------

* Added support for micro-second timestamps (available since Riemann 0.2.13),
  implemented by Mathieu Corbin, @mcorbin.

Miscellaneous changes
---------------------

* The parts of the test suite that require a running Riemann server are now
  disabled by default, and require setting the `RCC_NETWORK_TESTS` environment
  variable to a non-zero value, before running the test suite.

  Fixes an issue on systems that had something else listening on the port, or a
  Riemann with a different config than the one the test suite expected.

  Reported by Dave Cottlehuber, @dch.

riemann-c-client 1.9.1
======================
Released on 2016-09-30

Bugfixes
--------

* Fix the build on non-ELF systems, and systems that lack symbol versioning.
  (Thanks to @ilovezfs)
* Use the `PROTOBUF_C_CFLAGS` environment variable, when set.
  (Thanks to @ciomaire)
* Added some missing includes that prevented the library from compiling on
  FreeBSD.
  (Thanks to Dave Cottlehuber, @dch)
* Fixed an issue with how some of the symbols were versioned, which caused link
  failures in some situations.
  (Thanks to Dave Cottlehuber, @dch)

riemann-c-client 1.9.0
======================
Released on 2016-04-25

Features
--------

* Added the `RIEMANN_CLIENT_OPTION_TLS_PRIORITIES` client option, which can be
  used to set priorities for cipher suites to be used for a TLS session.

  The `riemann-client` tool also learned to accept a `-o priorities=` option,
  and set the above one appropriately.

riemann-c-client 1.8.1
======================
Released on 2015-08-28

Bugfixes
--------

* Tests use a different port for connection refused tests

  Because port 5557 is the default for (repl-server), use 5559 for
  testing for library behaviour in the face of connection
  refusal. This is to make local testing without a special config
  easier.

* Fixed a compile-time warning when compiling with GnuTLS 3.2

  When compiling with TLS support enabled, using GnuTLS 3.2, there was
  a harmless compile-time warning, which has now been corrected.

Miscellaneous changes
---------------------

* Completely new documentation

  Instead of using Doxygen to document our API, a new, prosaic
  documentation was written, that explains not only the hows, but the
  whys too. It is hoped that the new documentation is more
  approachable, and explains the library better.

riemann-c-client 1.8.0
======================
Released on 2015-06-04

Features
--------

* Added the `riemann_client_set_timeout` function.

  To be able to reliably detect whether a connection died, we need to
  set a timeout for the blocking operations. The new
  `riemann_client_set_timeout()` function does just that.

  Suggested by Fabien Wernli and others.

* Added a set of version macros.

  The `RCC_MAJOR_VERSION`, `RCC_MINOR_VERSION`, `RCC_PATCH_VERSION`
  and `RCC_VERSION_NUMBER` macros were added to aid developers in
  determining the version of the library at build-time without the
  need of `pkg-config`.

  The primary reason to do this would be to use features of the
  library, if available, optionally.

* The `riemann-client` utility can now forward messages from STDIN

  The `riemann-client` utility gained an `--stdin` option. Using this
  option, one can set up a template with the command line options, and
  send multiple events with different metrics and/or states, by piping
  lines to the utility's standard input.

  See the manual page for more information and an example.

Bugfixes
--------

* Handshake timeouts now work with GnuTLS 2.x too.

  When compiled with GnuTLS 2.x, the
  RIEMANN_CLIENT_OPTION_TLS_HANDSHAKE_TIMEOUT option was silently
  ignored. Now the timeouts are properly set up, but the timeout
  applies to all TLS operations, not only the handshake.

riemann-c-client 1.7.0
======================
Released on 2015-05-04

Features
--------

* Added the `riemann_communicate_query` and
  `riemann_communicate_event` functions.

  To make the `riemann_communicate()` API simpler for common use
  cases, two new functions were introduced, to be able to easily send
  queries and receive replies, and another to send a single event, and
  read the ACK back.

Bugfixes
--------

* Fix the TLS support to work with GnuTLS 3.1 tool

  Treat anything less than GnuTLS 3.3 as if it were GnuTLS 2.x, so
  that the library compiles and works for every possible GnuTLS
  version between 2.8 and 3.3+.

  Reported by Peter Czanik.

* Add a TLS example to the riemann-client(1) manual page.

  Suggested by Fabien Wernli.

riemann-c-client 1.6.1
======================
Released on 2015-04-23

Bugfixes
--------

* TLS support's GnuTLS dependency lowered even more

  Turns out that we need a little more work to support GnuTLS 2.8, and
  the previous release only lowered the requirement to 2.10+. With
  this release, 2.8+ is supported too.

  Reported by Fabien Wernli.

* Allow compiling with GCC < 4.4

  A #pragma used in the TLS code did not work with gcc < 4.4, this has
  been corrected.

  Reported by Fabien Wernli.

riemann-c-client 1.6.0
======================
Released on 2015-04-23

Features
--------

* TLS support's GnuTLS dependency lowered

  The minimum version of GnuTLS required was lowered from 3.3 to 2.8,
  so TLS support can be enabled on distributions and releases that
  ship with an older GnuTLS library.

  Requested by Fabien Wernli.

* `riemann_message_get_packed_size()` added

  To aid implementing clients that batch messages up until a certain
  size, the riemann_message_get_packed_size() method was added.

* `riemann_event_string_attribute_add()` added

  To make it easier to build up attributes, a convenience function was
  added that creates a `riemann_attribute_t` object out of key-value
  pairs, before attaching the result to an event.

  `riemann_event_set()` was also updated to handle this new style of
  attributes, along with the old way of explicitly using
  `riemann_attribute_t` objects.

* `riemann_communicate()` added to `<riemann/simple.h>`

  The new function takes care of both ways of communication: when
  sending events, it will read back the ACK when using TCP or TLS;
  when sending queries, it will read the results. When sending over
  UDP, it will fake an ACK for uniformity.

riemann-c-client 1.5.0
======================
Released on 2015-03-27

Features
--------

* TLS support

  The library now supports TLS connections via GnuTLS.

  To be able to properly set up a TLS-enabled connection,
  `riemann_client_connect()` and `riemann_client_create()` take
  optional extra arguments after the port if the type is
  `RIEMANN_CLIENT_TLS`.

  An older version of these functions are provided for ABI
  compatibility, and the new API is backwards-compatible too.

Bugfixes
--------

* `riemann-client query` handles error responses correctly.

  The `riemann-client query` command previously tried to dump the
  events of an error response too. It does not do that anymore,
  because in case of an error, we print the error itself, not the
  empty result set.

* `riemann_event_set()` accepts `NULL` strings as value properties.

   The `riemann_event_set()` function was changed to accept `NULL`
   strings as values for string properties. Instead of crashing in
   this case, the library now removes the property from the event.

riemann-c-client 1.4.0
======================
Released on 2015-03-17

Features
--------
* Add `riemann_message_append_events*()` functions.

  To make it easier to iteratively build up Riemann messages, the
  `riemann_message_append_events*()` family of functions were added.

  Requested by Christopher Gilbert <christopher.john.gilbert@gmail.com>.

* Add support for cloning objects.

  All of the riemann objects (attributes, queries, events and
  messages) are now clonable. The clone family of functions will do a
  deep copy of the source objects.

  Requested by Christopher Gilbert <christopher.john.gilbert@gmail.com>.

riemann-c-client 1.3.0
======================
Released on 2014-12-02

Features
--------

* Add `_va` variants for all relevant functions

  To make it easier to write wrappers, all functions that take a
  variable number of arguments now have a `_va()` variant, that takes
  a `va_list` instead.

  New functions are: `riemann_event_set_va()`,
  `riemann_event_create_va()`, `riemann_message_set_events_va()`,
  `riemann_message_create_with_events_va()`, riemann_send_va()`.

  Requested by Christopher Gilbert <christopher.john.gilbert@gmail.com>.

Bugfixes
--------

* Support C++ compilers

  All the public riemann-c-client headers now have extern "C" guards,
  so that the headers can be included in C++ projects too.

  Thanks to Jan Engelhardt <jengelh@inai.de> for the patch.

riemann-c-client 1.2.1
======================
Released on 2014-08-11

Bugfixes
--------

* Fix compilation on at least Fedora rawhide

  Instead of relying on implicitly pulling in `<inttypes.h>`, include
  the header explicitly.

* Do not include generated proto files in the tarball

  To avoid any conflicts between the protobuf-c used to generate
  sources when making the tarball, and the version used to build it,
  do not include these files at all, and just generate them at build
  time.

riemann-c-client 1.2.0
======================
Released on 2014-07-21

Features
--------
* `riemann_client_get_fd` added

  This new function can be used to gain access to the socket file
  descriptor used by the library. The intended use is for applications
  to be set various TCP or socket options, such as `TCP_CORK`, from
  within the application itself.

Bugfixes
--------

* The sample client hides empty metrics

  The example `riemann-client` tool will not display empty metrics
  anymore, and instead, will behave like the JSON output.

* `riemann_event_create()` error handling

  In `riemann_event_create()`, cache the result of
  `riemann_event_set_va()`, and use that for the `errno` value in the
  error branch, instead of trying to save `errno`, which the called
  function does not set.

* `riemann_message_from_buffer()` error handling

  In case serialisation fails, the function will now correctly set
  `errno`, making the error discoverable.

* Use `127.0.0.1` during tests

  Instead of using `localhost` (which could resolve to IPv6), use
  `127.0.0.1`, the same IP address Riemann will listen on by default.

Miscellaneous
-------------

* Test coverage

  The code underwent changes to simplify it, and the tests were
  extended too, reaching 100% code coverage.

riemann-c-client 1.1.1
======================
Released on 2014-01-23

While the `riemann-client` tool had the code to return query results
in JSON format since 1.0.3, it was not correctly wired into the build
system, and was always disabled. This release corrects that issue.

riemann-c-client 1.1.0
======================
Released on 2013-12-22

The major feature of this release is the simplified API available in
the `<riemann/simple.h>` header. The new API is for use when the whole
message can be constructed in a single step, and losing some of the
flexibility the library provides is not a problem.

Apart from that, a few bugs were also fixed in this release, such as
receiving events will now always wait for the full event. The test
suite was also made completely optional.

riemann-c-client 1.0.3
======================
Released on 2013-12-08

Minor internal changes were made to the library, in the spirit of
future extensibility. There were no functional changes made, however.

The `riemann-client` tool did receive a lot more updates again,
though, and now has support for returning query results in JSON (if
the json-c library is installed when compiling the package).

riemann-c-client 1.0.2
======================
Released on 2013-11-23

The library has not been touched at all with this release, but the
`riemann-client` tool received some updates and a manual page.

riemann-c-client 1.0.1
======================
Released on 2013-08-11

This release is a minor enhancement over the initial 1.0.0 release,
containing only a few improvements to error handling, including a fix
for a resource leak on event creation and connection failure.

All of `_free()` functions should now behave similarly, and set errno
to EINVAL when passed a NULL pointer.

The source also comes with a way to easily extract code coverage
information too, simply by typing `make coverage`.

riemann-c-client 1.0.0
======================
Released on 2013-06-28

Initial public release.
