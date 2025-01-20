#!/bin/sh

# The --force option rebuilds the configure script regardless of its timestamp in relation to that of the file configure.ac.
# The option --install copies some missing files to the directory, including the text files COPYING and INSTALL.
#autoreconf --force --install NÃO SEI PORQU~E MAS O ZEBOS NÃO GOSTA DISTO!!!!!
if test -f configure.ac; then
#	touch build/export.var
	libtoolize -fq
	aclocal --force
	autoheader -f
	touch NEWS README AUTHORS ChangeLog
	automake -acf
	autoconf -f
else
	echo "File 'configure.ac' not found!"
	exit 1
fi
