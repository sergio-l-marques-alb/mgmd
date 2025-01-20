#!/bin/bash

backupFile() {
	mv $1 $1_bckp;
}

restoreFile() {
	mv $1_bckp $1;
}

removeFile() {
	rm $1_bckp;
}

for file in $*
do
	echo "Checking header ->" $file;
	backupFile $file
	if make clean exec >/dev/null 2>&1;
	then
		echo "File was not needed.."
		removeFile $file
	else
		restoreFile $file
	fi	
done
