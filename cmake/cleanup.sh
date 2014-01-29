#!/bin/bash

# A quick and dirty script to remove old installs of
# libbtbb, libubertooth and associated Ubertooth tools

INSTALL_DIRS="/usr /usr/local"

LIBS="btbb ubertooth"

HEADERS="bluetooth_packet.h \
         bluetooth_piconet.h \
         bluetooth_le_packet.h \
         ubertooth_interface.h \
         ubertooth_control.h \
         ubertooth.h \
		 "

if [ "$1" == "-d" ]
then
	EXEC="-print -exec rm -f {} ;"
	echo "Deleting previous installs:"
else
	EXEC=-print
	echo 'Installed files, use "sudo cleanup.sh -d" to delete these files'
fi

for dir in $INSTALL_DIRS; do
	for lib in $LIBS; do
		find ${dir}/lib -name "lib$lib.so*" $EXEC
	done
	for header in $HEADERS; do
		find ${dir}/include -name "$header" $EXEC
	done
done
