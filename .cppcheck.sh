#!/bin/sh
#
# Script for handling cppcheck static analysis
#
#mkdir sa_results
TMPNAME=`date +%s`
cppcheck --help
cppcheck --template "{file}({line}): {severity} ({id}): {message}" \
         --enable=warning --force \
         --suppress=incorrectStringBooleanError \
         --suppress=invalidscanf --inline-suppr \
         --suppress=syntaxError \
         --language=c . 2> sa-results_$TMPNAME.txt
if [ -s sa-results_$TMPNAME.txt ]; then
      cat sa-results_$TMPNAME.txt
      exit 1
fi

