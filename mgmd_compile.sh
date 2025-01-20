#!/bin/sh

# README!
#
# This script configures and compiles MGMD module
#
# Input variables:
#		- $1 -> Card name
#
# Author:  Alexandre R. Santos (alexandre-r-santos@alticelabs.com)
# Date:    2017-06-01
#
#
# Author:   Filipe Silva (filipe-l-silva@alticelabs.com)
# Author:   Miguel Coelho (miguel-c-coelho@alticelabs.com)
# Date:    2024-07-09   

NUM_CPUS=`grep -c 'model name' /proc/cpuinfo`

INC_FILES=""
LIB_FILES="*.so* *.a"    

# In case card is not specified as a parameter, check if environment variables are set
if [ $# -eq 0 ]; then
  echo "[MGMD] Please use $0 <card name>!"
  exit 1
fi

echo "[MGMD] Configuring $1 card"

# Define specific variables according to the selected card
if [ "$1" == "cxo2t4" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then
      export COMPILER_DIR=/opt/fsl-qoriq/2.0/sysroots/x86_64-fslsdk-linux/usr/bin/powerpc-fsl-linux
      export COMPILER_PREFIX=powerpc-fsl-linux-
      export CROSSOPTS="--host=ppc-linux --build=$MACHTYPE"

      # Overide local variables with the ones comming from the makefile (if defined)
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export SDKTARGETSYSROOT="/opt/fsl-qoriq/2.0/sysroots/ppce500mc-fsl-linux"
      export LD_DEPS_OPT="--sysroot=$SDKTARGETSYSROOT"
      export CC_DEPS_OPT="-m32 -mhard-float -mcpu=e500mc --sysroot=$SDKTARGETSYSROOT" 
      export CC="${COMPILER_PREFIX}gcc ${CC_DEPS_OPT}"
      export LD="${COMPILER_PREFIX}ld ${LD_DEPS_OPT}"
      export PATH="${COMPILER_DIR}/usr/bin:/opt/fsl-qoriq/2.0/sysroots/x86_64-fslsdk-linux/usr/bin/../x86_64-fslsdk-linux/bin:${COMPILER_DIR}:${COMPILER_DIR}-uclibc:${COMPILER_DIR}-musl:$PATH"
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4096
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512 
  export PTIN_MGMD_PLATFORM_MAX_PORTS=672
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=672
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

# Define specific variables according to the selected card
elif [ "$1" == "cxo2t4r1" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then
      export COMPILER_DIR=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin
      export COMPILER_PREFIX=aarch64-linux-gnu-
      export CROSSOPTS="--host=arm-linux --build=i686-linux"

      # Overide local variables with the ones comming from the makefile (if defined)
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export CC="${COMPILER_PREFIX}gcc ${CC_DEPS_OPT}"
      export LD="${COMPILER_PREFIX}ld ${LD_DEPS_OPT}"
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4096
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512 
  export PTIN_MGMD_PLATFORM_MAX_PORTS=672
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=672
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

# Define specific variables according to the selected card
elif [ "$1" == "cxo2t3r1" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then
      export COMPILER_DIR=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin
      export COMPILER_PREFIX=aarch64-linux-gnu-
      export CROSSOPTS="--host=arm-linux --build=i686-linux"

      # Overide local variables with the ones comming from the makefile (if defined)
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export CC="${COMPILER_PREFIX}gcc ${CC_DEPS_OPT}"
      export LD="${COMPILER_PREFIX}ld ${LD_DEPS_OPT}"
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4096
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512 
  export PTIN_MGMD_PLATFORM_MAX_PORTS=672
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=672
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

elif [ "$1" == "cxo2t2" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then

      export COMPILER_DIR=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin
      export COMPILER_PREFIX=aarch64-linux-gnu-
      export CROSSOPTS="--host=arm-linux --build=i686-linux"

      # Overide local variables with the ones comming from the makefile (if defined)
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export CC="$COMPILER_DIR"/"$COMPILER_PREFIX"gcc
      export LD="$COMPILER_DIR"/"$COMPILER_PREFIX"ld
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4093
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512
  export PTIN_MGMD_PLATFORM_MAX_PORTS=224
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=224
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

elif [ "$1" == "cxo2t0" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then

      export COMPILER_DIR=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin
      export COMPILER_PREFIX=aarch64-linux-gnu-
      export CROSSOPTS="--host=arm-linux --build=i686-linux"

      # Overide local variables with the ones comming from the makefile (if defined)
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export CC="$COMPILER_DIR"/"$COMPILER_PREFIX"gcc
      export LD="$COMPILER_DIR"/"$COMPILER_PREFIX"ld
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4093
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512
  export PTIN_MGMD_PLATFORM_MAX_PORTS=44
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=44
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

elif [ "$1" == "cxo2t0e" ]; then

  BOARD=$1

  if [ -z $DESTDIR ]; then

      export COMPILER_DIR=/opt/gcc-linaro-7.2.1-2017.11-x86_64_aarch64-linux-gnu/bin
      export COMPILER_PREFIX=aarch64-linux-gnu-
      export CROSSOPTS="--host=arm-linux --build=i686-linux"
      export COMPILER_DIR="${TOOLCHAIN_BIN_DIR:-$COMPILER_DIR}"
      PREFIX=`echo $COMPILER | awk -F'/' '{print $NF}'`
      if [ ! -z $PREFIX ]; then
        export COMPILER_PREFIX=$PREFIX;
      fi
      export CC="$COMPILER_DIR"/"$COMPILER_PREFIX"gcc
      export LD="$COMPILER_DIR"/"$COMPILER_PREFIX"ld
  fi

  export PTIN_MGMD_PLATFORM_MAX_CHANNELS=4093
  export PTIN_MGMD_PLATFORM_MAX_WHITELIST=16384
  export PTIN_MGMD_PLATFORM_MAX_CLIENTS=512
  export PTIN_MGMD_PLATFORM_MAX_PORTS=96
  export PTIN_MGMD_PLATFORM_MAX_PORT_ID=96
  export PTIN_MGMD_PLATFORM_MAX_SERVICES=128
  export PTIN_MGMD_PLATFORM_MAX_SERVICE_ID=(32768+4096)
  export PTIN_MGMD_PLATFORM_ADMISSION_CONTROL_SUPPORT=1
  export PTIN_MGMD_PLATFORM_ROOT_PORT_IS_ON_MAX_PORT_ID=1

else
  echo "[MGMD] Card $BOARD is not valid!"
  exit 1
fi

#################### DO NOT CHANGE ANY LINE BELOW! ####################

# Define the main MGMD path (where autogen.sh will generate the configure file)
MGMD_BASE_PATH=$(cd $(dirname "$0") ; pwd -P )
MGMD_CONFIGURE=$MGMD_BASE_PATH/configure

OUTPUT_PATH=$MGMD_BASE_PATH/output/$BOARD 
EXPORT_FILE=$OUTPUT_PATH/export.var

if [ -z $BUILDIR ]; then
 BUILDIR=$MGMD_BASE_PATH/build_dir/$BOARD 
fi

if [ -z $BUILDIR_LOCAL ]; then
 BUILDIR_LOCAL=$MGMD_BASE_PATH/build_dir_local/$BOARD 
fi

# Bash mutex implementation
readonly LOCKDIR=$MGMD_BASE_PATH/.mgmd.lock
readonly LOCK_SLEEP=2

lock() {
  # create lock directory
  echo -n "[MGMD] Locking $LOCKDIR: "
  
  # acquier the lock
  while (! mkdir $LOCKDIR >/dev/null 2>&1); do
    sleep $LOCK_SLEEP;
  done

  # Enable trap to detect CTRL-C or kill commands
  trap "rm -rf ${LOCKDIR}; echo '[MGMD] Lock directory unlocked by trap!'; exit" INT TERM

  echo "done!"
  return 0;
}

unlock() {
  # remove the lock directory
  rm -rf $LOCKDIR >/dev/null 2>&1

  # Disable trap...
  trap "exit" INT TERM

  echo "[MGMD] Unlocking directory $LOCKDIR: done!"
  return 0
}

# Toolchain and SYS_ROOT_DIR definition
if [ -z $DESTDIR ]; then
    export DESTDIR=$OUTPUT_PATH/rfs
    export SYSROOTDIR=$DESTDIR
    export PREFIXDIR="/usr/local"
    export ETCDIR=$PREFIXDIR/etc
    export PKG_CONFIG_PATH=$DESTDIR/$PREFIXDIR/lib/pkgconfig
    export PATH=$PATH:$COMPILER_DIR
    if [ ! -z "$DIR_INCLUDE" ]; then
        export CFLAGS="$SYSROOT -I$DIR_INCLUDE"
    else
        export CFLAGS="$SYSROOT -I$BUILDIR_LOCAL$PREFIXDIR/include -I$BUILDIR$PREFIXDIR/include"
    fi
    export LIBS="-llogger -lz"                                                   
    if [ ! -z "$DIR_LIBS" ]; then
        export LDFLAGS="-L$DIR_LIBS"
    else
        export LDFLAGS="-L$BUILDIR_LOCAL$PREFIXDIR/lib -L$BUILDIR$PREFIXDIR/lib"
    fi
    export STRIP="$COMPILER_DIR"/"$COMPILER_PREFIX"strip
    export CXX="$COMPILER_DIR"/"$COMPILER_PREFIX"g++
    export AR="$COMPILER_DIR"/"$COMPILER_PREFIX"ar
    export NM="$COMPILER_DIR"/"$COMPILER_PREFIX"nm
    export RANLIB="$COMPILER_DIR"/"$COMPILER_PREFIX"ranlib
    export READELF="$COMPILER_DIR"/"$COMPILER_PREFIX"readelf
    export OBJCOPY="$COMPILER_DIR"/"$COMPILER_PREFIX"objcopy
    export OBJDUMP="$COMPILER_DIR"/"$COMPILER_PREFIX"objdump
    export INSTALL=/usr/bin/install
else
    if [ ! -z "$DIR_INCLUDE" ]; then
       export CFLAGS="$SYSROOT -I$DIR_INCLUDE"
    fi
    if [ ! -z "$DIR_LIBS" ]; then
        export LDFLAGS="-L$DIR_LIBS"
    fi
    export LIBS="-llogger -lz"
fi

# Check if clean command is issued
if [ "$2" == "clean" ]; then
  rm -f $MGMD_CONFIGURE
  rm -rf $OUTPUT_PATH
  echo "[MGMD] Clean complete!"
  exit 0
fi

# autogen.sh script must be executed once! It must then be protected by a mutex
lock

# Run autogen.sh if 'configure' file does not exist
if [ ! -f $MGMD_CONFIGURE ]; then
  echo "[MGMD] File '$MGMD_CONFIGURE' not found!"
  
  echo "[MGMD] Running autogen.sh from the main MGMD path (protected with a mutex)"
  cd $MGMD_BASE_PATH
  sh autogen.sh
  cd - >/dev/null
  
fi

unlock

# Create output path if it doesn't exist
mkdir -pv $OUTPUT_PATH                 

MGMD_REV=`svn info $MGMD_BASE_PATH | grep 'Revision' | awk '{print $2}'`
MGMD_CONF_REV=`cat $MGMD_CONFIGURE | grep "PACKAGE_VERSION=" -m 1 | sed "s/[^0-9]*//; s/'//; s/M//" | awk -F. '{print $4}'`

echo -n "[MGMD] Checking revision svn=$MGMD_REV configure=$MGMD_CONF_REV: "
if [ "$MGMD_REV" != "$MGMD_CONF_REV" ]; then
  echo "don't match!"
  
  echo "[MGMD] Running autogen.sh from the main MGMD path (protected with a mutex)"
  lock
  cd $MGMD_BASE_PATH
  sh autogen.sh
  cd - >/dev/null
  unlock

  echo "[MGMD] Running configure..."
  cd $MGMD_BASE_PATH
  $MGMD_CONFIGURE --prefix=$PREFIXDIR $CROSSOPTS --with-liblogger
  
  if [ $? -ne 0 ]; then
    echo "[MGMD] Error while running configure!"
    cd - >/dev/null
    exit 1
  fi
  
  cd - >/dev/null
else
  echo "match!"
fi

echo -n "[MGMD] Checking Makefile: "
if [ ! -f $OUTPUT_PATH/Makefile ]; then
  echo "not found!"
  echo "[MGMD] Running configure..."
  
  cd $OUTPUT_PATH
  $MGMD_CONFIGURE --prefix=$PREFIXDIR $CROSSOPTS --with-liblogger
  
  if [ $? -ne 0 ]; then
    echo "[MGMD] Error while running configure!"
    cd - >/dev/null
    exit 1
  fi
  
  cd - >/dev/null
else
  echo "found! (skipping configuration)"
fi

echo "[MGMD] Compiling..."
make -j$NUM_CPUS -C $OUTPUT_PATH install
 

if [ $? -ne 0 ]; then
  echo "[MGMD] Error while compiling!"
  exit 1
fi

# Update output file
echo "[MGMD] Updating binaries and include files..."
board=`echo $BOARD | awk '{print tolower($0)}'`

# Create buildir directories and copy respective files if applicable
if [ ! -z "$INC_FILES" ]; then
    mkdir -pv $BUILDIR/usr/local/include/

    for FILE in $INC_FILES; do
        find $MGMD_BASE_PATH/src/ -name $FILE | xargs cp -uvP --target-directory=$BUILDIR/usr/local/include/.
    done
fi

if [ ! -z "$LIB_FILES" ]; then
    mkdir -pv $BUILDIR_LOCAL/usr/local/lib/

    for FILE in $LIB_FILES; do
        find $OUTPUT_PATH/src/ -name $FILE | xargs cp -uvP --target-directory=$BUILDIR_LOCAL/usr/local/lib/.
    done
fi

# If build_dir_local exists, then also copy files to that directory
# Create buildir directories and copy respective files if applicable
if [ ! -z "$INC_FILES" ]; then
  mkdir -pv $BUILDIR_LOCAL/usr/local/include/

  for FILE in $INC_FILES; do
    find $MGMD_BASE_PATH/src/ -name $FILE | xargs cp -uvP --target-directory=$BUILDIR_LOCAL/usr/local/include/.
  done
fi

if [ ! -z "$LIB_FILES" ]; then
  mkdir -pv $BUILDIR_LOCAL/usr/local/lib/

  for FILE in $LIB_FILES; do
    find $OUTPUT_PATH/src/ -name $FILE | xargs cp -uvP --target-directory=$BUILDIR_LOCAL/usr/local/lib/.
  done
fi
 
echo "[MGMD] Compilation done!"


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

