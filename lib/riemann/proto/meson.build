# -*- meson -*-

protoSrcC = custom_target(
  'protobuf-c',
  input: 'riemann.proto',
  output: ['riemann.pb-c.c'],
  command: [protoc, '@INPUT@', '--c_out=lib/riemann/proto', '-I@SOURCE_DIR@/lib/riemann/proto'],
)

protoSrcH = custom_target(
  'protobuf-h',
  input: 'riemann.proto',
  output: ['riemann.pb-c.h'],
  command: [protoc, '@INPUT@', '--c_out=lib/riemann/proto', '-I@SOURCE_DIR@/lib/riemann/proto'],
  install: true,
  install_dir: get_option('includedir') + '/riemann/proto'
)

protoSrc = [protoSrcC, protoSrcH]
