# -*- meson -*-

ver_arr = meson.project_version().split('.')

conf = configuration_data()
conf.set('MAJOR_VERSION', ver_arr[0])
conf.set('MINOR_VERSION', ver_arr[1])
conf.set('PATCH_VERSION', ver_arr[2])
conf.set_quoted('PACKAGE_VERSION', meson.project_version())
conf.set_quoted('PACKAGE_STRING', 'riemann-c-client ' + meson.project_version())
conf.set('NUMBER_VERSION',
            ver_arr[0].to_int() * 256 * 256 +
            ver_arr[1].to_int() * 256 +
            ver_arr[2].to_int())

if jsonc.found()
  conf.set('HAVE_JSON_C', 1)
endif
if check.found()
  conf.set('HAVE_CHECK', 1)
endif

if get_option('disable-tls')
  conf.set('HAVE_GNUTLS', 0)
else
  if gnutls.found()
    conf.set('HAVE_GNUTLS', 1)
  else
    conf.set('HAVE_GNUTLS', 0)
  endif
endif

pkgconf = conf
pkgconf.set('VERSION', meson.project_version())
pkgconf.set('prefix', get_option('prefix'))
pkgconf.set('exec_prefix', '${prefix}')
pkgconf.set('libdir', '${prefix}/@0@'.format(get_option('libdir')))
pkgconf.set('includedir', '${prefix}/@0@'.format(get_option('includedir')))

configure_file(output: 'platform.h',
               configuration: conf)

configure_file(output: 'riemann-client.h',
               input: 'riemann-client.h.in',
               configuration: conf,
               install_dir: get_option('includedir') + '/riemann')
configure_file(output: 'riemann-client.pc',
               input: 'riemann-client.pc.in',
               configuration: pkgconf,
               install_dir: '@0@/pkgconfig'.format(get_option('libdir')))

subdir('proto')

sources = [
  protoSrc,
  'attribute.c',
  'attribute.h',
  'client.c',
  'client.h',
  'client/tcp.c',
  'client/tcp.h',
  'client/tls.c',
  'client/tls.h',
  'client/udp.c',
  'client/udp.h',
  'event.c',
  'event.h',
  'message.c',
  'message.h',
  '_private.h',
  'query.c',
  'query.h',
  'simple.c',
  'simple.h'
]

headers = [
  'client.h',
  'event.h',
  'message.h',
  'attribute.h',
  'query.h',
  'simple.h'
]

deps = [ libprotoc, gnutls ]

## TODO:
## - proper versioning
## - symbol versioning

install_headers(headers, subdir : 'riemann')
libriemann_c = shared_library(
  'riemann-client', sources,
  soversion: '0',
  version: '0.0.0',
  dependencies: deps,
  include_directories: include_directories('..'),
  install: true
)
