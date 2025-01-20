#!/bin/sh

# README!
#
# This script creates a package of a module
#
# Input variables:
#   $1 -> Card name
#   or DEV_BOARD must be defined
#
# Author:  Rui Fernandes (rui-f-fernandes@alticelabs.com)
# Date:    2018-03-07
#
# Author:  Alexandre Santos (alexandre-r-santos@alticelabs.com)
# Author:  Hugo Araujo (hugo-f-araujo@alticelabs.com)
# Date:    2018-08-01
#
# Author:   Filipe Silva (filipe-l-silva@alticelabs.com)
# Author:   Miguel Coelho (miguel-c-coelho@alticelabs.com)
# Date:    2024-06-27 
#
# NOTE: update the APPxxxx variables to adapt to any other app/library


APPTAG="MGMD"
APPNAME="mgmd"

BIN_FILES="mgmd.cli"
LIB_FILES="*.so*"

BASE_PATH="$(cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd)"

RFS_DIR=$BASE_PATH/rfs
OUTPUT_DIR=$BASE_PATH/output
DEV_BOARD_SW=$DEV_BOARD
DATE=`date`

BUILDIR_LOCAL=$BASE_PATH/build_dir_local
BUILDIR=$BASE_PATH/build_dir

# In case card is not specified as a parameter, check if environment variables are set
if [ $# -eq 0 ] && [ -z $DEV_BOARD ]; then
    echo "[$APPTAG] Please use $0 <card name> or define DEV_BOARD variable!"
    exit 1
fi


# Create log file
LOG_FILE=$BASE_PATH/create_package.log
echo "-- start script --" > $LOG_FILE
echo "" >> $LOG_FILE


# If one parameter is given, use it as the board name
if [ $# -ge 1 ]; then
    DEV_BOARD_SW=$1
fi

# Clear BIN_FILES for the cards where the binary is not executed
#if [ "$DEV_BOARD_SW" == "cxo2t4-sf" ] || [ "$DEV_BOARD_SW" == "cxo2t4" ] || [ "$DEV_BOARD_SW" == "cxo2t0" ]|| [ "$DEV_BOARD_SW" == "cxo2t2" ]; then
#    BIN_FILES=""
#fi

echo "Creating package of $APPNAME for $DEV_BOARD_SW..."
echo "Creating package of $APPNAME for $DEV_BOARD_SW..." >> $LOG_FILE

# Get app svn revision and define several variables that depend on it
file=version.txt
VERSION=$(cat "$file")

svn_rev=`svnversion -n | sed -e 's/.*://' -e 's/[A-Z]*$$//'`
MODULE=$APPNAME-$DEV_BOARD_SW-$VERSION-r$svn_rev
image_tgz=$MODULE.tgz

# By default, clean is not issued

#echo "Cleaning $APPNAME for $DEV_BOARD_SW card..." >> $LOG_FILE
#sh ./${APPNAME}_compile.sh $DEV_BOARD_SW clean>> $LOG_FILE
#if [ $? -ne 0 ]; then
#  echo "ERROR cleaning $APPNAME!!!"

# Create build_dir_local folder if it doesn't exist
if [ ! -e $BUILDIR_LOCAL/$DEV_BOARD_SW ]; then
    echo "$BUILDIR_LOCAL/$DEV_BOARD_SW  doesn't exist... Creating it"
    mkdir -p $BUILDIR_LOCAL/$DEV_BOARD_SW
else
    echo "$BUILDIR_LOCAL/$DEV_BOARD_SW folder exist" >> $LOG_FILE
fi

#if [ -e $BUILDIR ]; then
    #if [ ! -L $BUILDIR ] 
    #then
    #    echo "$BUILDIR is not symlink" >> $LOG_FILE
    #else
    #    echo "$BUILDIR is symlink" >> $LOG_FILE
   # fi
#else
    #echo "ERROR build_dir directory doesn't exist !!!" >> $LOG_FILE
    #echo "ERROR build_dir directory doesn't exist !!!"
    #echo "PLEASE create symbolic link for build_dir"
    #exit 1;
    #ln -s /home/olt_shared/oltosng/build_dir_4.16/ $BUILDIR
#fi

# DESTDIR will point to build_dir location (external libs and includes)
if [ -z $DESTDIR ]; then
    DESTDIR=$BUILDIR_LOCAL/$DEV_BOARD_SW
fi

echo "Compiling $APPNAME for $DEV_BOARD_SW ..." >> $LOG_FILE
sh $BASE_PATH/${APPNAME}_compile.sh $DEV_BOARD_SW >> $LOG_FILE 2>>$LOG_FILE
if [ $? -ne 0 ]; then
    echo "ERROR compiling $APPNAME!!!"
    exit 1;
fi

# Check if DESTDIR exists (should have been created during compilation process)
if [ ! -e $DESTDIR ]; then
    echo "ERROR!!! $DESTDIR doesn't exist!" >> $LOG_FILE
    echo "ERROR!!! $DESTDIR doesn't exist!"
    exit 1;
fi

# Create package folder if it doesn't exist
if [ ! -e $DESTDIR/packages ]; then
    echo "$DESTDIR/packages doesn't exist... Creating it"
    mkdir -p $DESTDIR/packages
fi

if [ ! -e $OUTPUT_DIR ]; then
    mkdir $OUTPUT_DIR
else
    echo "$OUTPUT_DIR folder exists" >> $LOG_FILE
fi

echo "Building $MODULE version ${APPNAME}-$VERSION-r$svn_rev ..." >> $LOG_FILE 

# Create version file
VERSION_FILE=$BASE_PATH/${APPNAME}.ver
echo echo Modular OLT $MODULE $VERSION-r$svn_rev > $VERSION_FILE
echo echo $DATE >> $VERSION_FILE
chmod 777 $VERSION_FILE

mkdir -pv $RFS_DIR/$DEV_BOARD_SW/usr/local/scripts >> $LOG_FILE
mv -v $VERSION_FILE $RFS_DIR/$DEV_BOARD_SW/usr/local/scripts >> $LOG_FILE

# Copy libs and binary files to the build path
if [ ! -z "$LIB_FILES" ]; then
    mkdir -pv $RFS_DIR/$DEV_BOARD_SW/usr/local/lib >> $LOG_FILE

    for FILE in $LIB_FILES; do
        find $OUTPUT_DIR/$DEV_BOARD_SW/src -name $FILE | xargs cp -uvP --target-directory=$RFS_DIR/$DEV_BOARD_SW/usr/local/lib/. >> $LOG_FILE
    done
fi

if [ ! -z "$BIN_FILES" ]; then
    mkdir -pv $RFS_DIR/$DEV_BOARD_SW/usr/local/sbin >> $LOG_FILE

    for FILE in $BIN_FILES; do
        find $OUTPUT_DIR/$DEV_BOARD_SW/src -name $FILE | xargs cp -uvP --target-directory=$RFS_DIR/$DEV_BOARD_SW/usr/local/sbin/. >> $LOG_FILE
    done
fi

# If log directory doesn't exist, create it
if [ ! -d "$RFS_DIR/$DEV_BOARD_SW/var/log/${APPNAME}-logs/" ]; then
    mkdir -pv $RFS_DIR/$DEV_BOARD_SW/var/log/${APPNAME}-logs >> $LOG_FILE
fi 


# Create tgz file
echo "Preparing tarball for $DEV_BOARD_SW..."
cd $RFS_DIR/$DEV_BOARD_SW
rm -f *.tgz 
tar czvf $image_tgz --exclude='.svn*' * --owner=root --group=root >> $LOG_FILE 
if [ $? -ne 0 ]; then
    echo "ERROR creating tarball!!!" >> $LOG_FILE
    cd - >>/dev/null
    exit 1;
fi

mv -v $image_tgz $DESTDIR/packages/. >> $LOG_FILE
cd - >>/dev/null

# Done without errors
echo "" >> $LOG_FILE
echo "-- end script --" >> $LOG_FILE

echo "Tarball of $DEV_BOARD_SW created and moved to $DESTDIR/packages"

exit 0
