# -*- meson -*-

sources = [
  'riemann-client.c'
]

deps = [ jsonc ]

install_man('riemann-client.1')

rcc = executable(
  'riemann-client', sources,
  include_directories: include_directories('../lib'),
  dependencies: deps,
  link_with: libriemann_c,
  install: true
)
