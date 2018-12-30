# -*- meson -*-
project('riemann-c-client', 'c', version: '1.10.4')

protoc = find_program('protoc-c', required: true)
libprotoc = dependency('libprotobuf-c', required: true)
jsonc = dependency('json-c', required: false, version: '>= 0.11')
check = dependency('check', required: false)

if not get_option('disable-tls')
  gnutls = dependency('gnutls', version: '>= 2.8', required: get_option('require-tls'))
endif

subdir('lib/riemann')
subdir('src')
