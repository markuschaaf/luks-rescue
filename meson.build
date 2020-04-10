project('luks-rescue', ['cpp', 'c'],
          version: '0.1.0',
    meson_version: '>= 0.50.0',
  default_options: [ 'warning_level=2',
                     'cpp_std=gnu++17',
                   ],
)

nettle = dependency( 'nettle' )
subdir('src')
executable( 'luks-rescue', 'src/luks-rescue.cpp', 'src/die.cpp', dependencies : nettle, install : true )
executable( 'mark-sectors', 'src/mark-sectors.cpp', install : true )
