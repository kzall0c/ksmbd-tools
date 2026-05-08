configure_file(
  input: 'ksmbd.selftest.in',
  output: 'ksmbd.selftest',
  install_dir: get_option('sbindir'),
  install_mode: 'rwxr-xr-x',
  configuration: in_data,
)

configure_file(
  input: 'ksmbd.selftest.8.in',
  output: 'ksmbd.selftest.8',
  install_dir: get_option('mandir') / 'man8',
  configuration: in_data,
)

install_data(
  sources: 'ksmbd.selftest.conf',
  install_dir: get_option('sysconfdir') / 'ksmbd',
)

selftest_unit = executable(
  'ksmbd.selftest-unit',
  'selftest.c',
  'user.c',
  '../tools/management/user.c',
  '../tools/management/share.c',
  '../tools/management/tree_conn.c',
  '../tools/management/session.c',
  '../tools/config_parser.c',
  '../tools/tools.c',
  include_directories: include_dirs,
  c_args: [
    '-DSYSCONFDIR="@0@"'.format(get_option('prefix') / get_option('sysconfdir')),
    '-DRUNSTATEDIR="@0@"'.format(runstatedir),
  ],
  dependencies: [
    glib_dep,
    libnl_dep,
    pthread_lib,
  ],
  link_with: [
    addshare_lib,
    adduser_lib,
    control_lib,
    mountd_lib,
  ],
  build_by_default: false,
)

test('unit', selftest_unit)
