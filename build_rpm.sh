#!/bin/bash -xe
#
# Build from master by default.
# $1 argument can be used to specify another ref (i.e. user-dev).
#

GITREF=${1:-master}
COMMIT_ID=$(git show-ref --hash refs/heads/$GITREF)
SHORT_COMMIT_ID=$(git show-ref --hash=7 refs/heads/$GITREF)
TAR_FILE=joy-$SHORT_COMMIT_ID.tar
TGZ_FILE=joy-$SHORT_COMMIT_ID.tar.gz

git archive --format=tar --prefix="joy/" $COMMIT_ID > $TAR_FILE
if [ "$?" != 0 ]; then
    echo Failed to create git archive tar
    exit 1
fi
#if [ "$GITREF" != "master" ]; then
#    tar -uf $TAR_FILE ../joy/Makefile ../joy/install/install-sh ../joy/rpm/joy.spec ../joy/src/anon.c
#    if [ "$?" != 0 ]; then
#        echo Failed to update archive tar
#        exit 1
#    fi
#fi
gzip -c $TAR_FILE > $TGZ_FILE
if [ "$?" != 0 ]; then
    echo Failed to gzip archive tar
    exit 1
fi
rpmbuild -tb --define "COMMIT_ID $COMMIT_ID" --define "dist .el7" ./$TGZ_FILE
if [ "$?" != 0 ]; then
    echo Failed to build RPM
    exit 1
fi
rm -f $TAR_FILE $TGZ_FILE
