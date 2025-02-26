#!/bin/sh

# Define the main MGMD path (where autogen.sh will generate the configure file)
CONFIGURE="../configure"
EXPORT_FILE="./export.var"

# configure file must exist
if [ ! -f $CONFIGURE ]; then
  echo "File '$CONFIGURE' not found!"
  echo "Please run autogen.sh from the main path"
  exit 1
fi

# Toolchain and SYS_ROOT_DIR definition
export DESTDIR=$PWD/rfs
export SYSROOTDIR=$DESTDIR
export PREFIXDIR=/usr/local/ptin
export ETCDIR=$PREFIXDIR/etc
export PKG_CONFIG_PATH=$DESTDIR$PREFIXDIR/lib/pkgconfig
export TARGET_PPC=ppc_85xxDP
export CROSS_COMPILE=$TARGET_PPC-
export COMPILER_DIR=/opt/eldk/usr/bin
export COMPILER_PREFIX=ppc_85xxDP-
export PATH=$PATH:$COMPILER_DIR
#export INCLUDEDIR="/opt/eldk/usr/bin/usr/include"
export CROSSOPTS="--host=ppc-linux --build=$MACHTYPE"
#export CFLAGS="-I$INCLUDEDIR -I$SYSROOTDIR$PREFIXDIR/include"
#export LIBDIR="/opt/ppc-ptin-4.2.2/$TARGET_PPC/usr/lib"
export LIBS=
export LD_LIBRARY_PATH="$LD_LIBRARY_PATH"
#export LD_PATH="-L$LIBDIR -L$SYSROOTDIR$PREFIXDIR/lib"
#export LDFLAGS="$LD_PATH"
#export CPPFLAGS="-I$INCLUDEDIR -I$SYSROOTDIR$PREFIXDIR/include"   
export STRIP="$COMPILER_DIR"/"$COMPILER_PREFIX"strip
export CC="$COMPILER_DIR"/"$COMPILER_PREFIX"gcc
export CXX="$COMPILER_DIR"/"$COMPILER_PREFIX"g++
export AR="$COMPILER_DIR"/"$COMPILER_PREFIX"ar
export LD="$COMPILER_DIR"/"$COMPILER_PREFIX"ld
export NM="$COMPILER_DIR"/"$COMPILER_PREFIX"nm
export RANLIB="$COMPILER_DIR"/"$COMPILER_PREFIX"ranlib
export READELF="$COMPILER_DIR"/"$COMPILER_PREFIX"readelf
export OBJCOPY="$COMPILER_DIR"/"$COMPILER_PREFIX"objcopy
export OBJDUMP="$COMPILER_DIR"/"$COMPILER_PREFIX"objdump
export INSTALL=/usr/bin/install

# MGMG specific variables definition
export PTIN_MGMD_PLATFORM_CTRL_TIMEOUT=
export PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE=
export PTIN_MGMD_PLATFORM_STACK_SIZE=
export PTIN_MGMD_PLATFORM_MAX_CHANNELS=
export PTIN_MGMD_PLATFORM_MAX_WHITELIST=
export PTIN_MGMD_PLATFORM_MAX_CLIENTS=
export PTIN_MGMD_PLATFORM_MAX_PORTS=
export PTIN_MGMD_PLATFORM_MAX_PORT_ID=
export PTIN_MGMD_PLATFORM_MAX_SERVICES=
export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=
export PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE=
export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=
export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=
export PTIN_MGMD_PLATFORM_SVN_VERSION=
export PTIN_MGMD_PLATFORM_SVN_RELEASE=
export PTIN_MGMD_PLATFORM_SVN_PACKAGE=

# Save all variables in export.var file
echo '.EXPORT_ALL_VARIABLES:' > $EXPORT_FILE
echo "export DESTDIR=$DESTDIR" >> $EXPORT_FILE
echo "export SYSROOTDIR=$SYSROOTDIR" >> $EXPORT_FILE
echo "export PREFIXDIR=$PREFIXDIR" >> $EXPORT_FILE
echo "export ETCDIR=$ETCDIR" >> $EXPORT_FILE
echo "export PKG_CONFIG_PATH=$PKG_CONFIG_PATH" >> $EXPORT_FILE
echo "export TARGET_PPC=$TARGET_PPC" >> $EXPORT_FILE
echo "export CROSS_COMPILE=$CROSS_COMPILE" >> $EXPORT_FILE
echo "export COMPILER_DIR=$COMPILER_DIR" >> $EXPORT_FILE
echo "export PATH=$PATH" >> $EXPORT_FILE
echo "export COMPILER_PREFIX=$COMPILER_PREFIX" >> $EXPORT_FILE
echo "export CROSSOPTS=$CROSSOPTS" >> $EXPORT_FILE
echo "export CFLAGS=$CFLAGS" >> $EXPORT_FILE
echo "export LIBDIR=$LIBDIR" >> $EXPORT_FILE
echo "export LIBS=$LIBS" >> $EXPORT_FILE
echo "export LD_PATH=$LD_PATH" >> $EXPORT_FILE
echo "export LD_LIBRARY_PATH=$LD_LIBRARY_PATH" >> $EXPORT_FILE
echo "export LDFLAGS=$LDFLAGS" >> $EXPORT_FILE
echo "export INCLUDEDIR=$INCLUDEDIR" >> $EXPORT_FILE
echo "export CPPFLAGS=$CPPFLAGS" >> $EXPORT_FILE
echo "export STRIP=$STRIP" >> $EXPORT_FILE
echo "export CC=$CC" >> $EXPORT_FILE
echo "export CXX=$CXX" >> $EXPORT_FILE
echo "export AR=$AR" >> $EXPORT_FILE
echo "export LD=$LD" >> $EXPORT_FILE
echo "export NM=$NM" >> $EXPORT_FILE
echo "export RANLIB=$RANLIB" >> $EXPORT_FILE
echo "export READELF=$READELF" >> $EXPORT_FILE
echo "export OBJCOPY=$OBJCOPY" >> $EXPORT_FILE
echo "export OBJDUMP=$OBJDUMP" >> $EXPORT_FILE
echo "export INSTALL=$INSTALL" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_CTRL_TIMEOUT=$PTIN_MGMD_PLATFORM_CTRL_TIMEOUT" >> $EXPORT_FILE   
echo "export PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE=$PTIN_MGMD_PLATFORM_MSGQUEUE_SIZE" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_STACK_SIZE=$PTIN_MGMD_PLATFORM_STACK_SIZE" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_CHANNELS=$PTIN_MGMD_PLATFORM_MAX_CHANNELS" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_WHITELIST=$PTIN_MGMD_PLATFORM_MAX_WHITELIST" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_CLIENTS=$PTIN_MGMD_PLATFORM_MAX_CLIENTS" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_PORTS=$PTIN_MGMD_PLATFORM_MAX_PORTS" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_PORT_ID=$PTIN_MGMD_PLATFORM_MAX_PORT_ID" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_SERVICES=$PTIN_MGMD_PLATFORM_MAX_SERVICES" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=$PTIN_MGMD_PLATFORM_MAX_SERVICE_ID" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE=$PTIN_MGMD_PLATFORM_MAX_FRAME_SIZE" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=$PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=$PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_SVN_RELEASE=$PTIN_MGMD_PLATFORM_SVN_RELEASE" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_SVN_VERSION=$PTIN_MGMD_PLATFORM_SVN_VERSION" >> $EXPORT_FILE
echo "export PTIN_MGMD_PLATFORM_SVN_PACKAGE=$PTIN_MGMD_PLATFORM_SVN_PACKAGE" >> $EXPORT_FILE

# Finally run configure script 
$CONFIGURE --prefix=$PREFIXDIR $CROSSOPTS

