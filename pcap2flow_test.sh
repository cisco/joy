#!/bin/sh 
#
# pcap2flow_test.sh
#
# test driver for pcap2flow program

# if you have a set of interesting or varied pcap files, you can set
# this variable to refer to them, to improve test coverage
# 
data=sample.pcap


if [ "$1" != "-f" ]; then
    # avoid clobbering somebody else's files, just in case there is a 
    # name collision with the temporary files that this script uses
    #
    if [ -f tmpfile ]; then
	echo "error: file tmpfile exists, possibly from a previous run of this "
	echo "program; delete it before running this program (if it is not needed)"
	echo "or run this program with the -f option to force its deletion"
	echo ""
	exit 255
    fi
    if [ -f tmpfile2 ]; then
	echo "error: file tmpfile2 exists, possibly from a previous run of this "
	echo "program; delete it before running this program (if it is not needed)"
	echo "or run this program with the -f option to force its deletion"
	echo ""
	exit 255
    fi
fi


# test different data feature capture options, in offline mode
#
# note: hd=1 produces improper JSON, and thus we skip that test for now
#
for args in "output=tmpfile"                                     \
            "output=tmpfile bidir=1"                             \
            "output=tmpfile bidir=1 zeros=1"                     \
            "output=tmpfile bidir=1 dist=1"                      \
            "output=tmpfile bidir=1 entropy=1"                   \
            "output=tmpfile bidir=1 tls=1"                       \
            "output=tmpfile bidir=1 idp=1400"                    \
            "output=tmpfile bidir=1 num_pkts=0"                  \
            "output=tmpfile bidir=1 num_pkts=101"                \
            "output=tmpfile bidir=1 anon=internal.net"           \
            "output=tmpfile bidir=1 label=internal:internal.net" \
            "output=tmpfile bidir=1 classify=1"                  \
            "output=tmpfile bidir=1 wht=1"                       \
            "output=tmpfile bidir=1 dns=1"                       \
            "output=tmpfile bidir=1 bpf=tcp"                     \
            "output=tmpfile bidir=1 type=1"; do
    echo -n "testing pcap2flow with arguments" $args "... "
    if ./pcap2flow $args $data; then
	if ./query.py tmpfile > tmpfile2; then
	    echo "passed"
	else
	    echo "failed: output was not valid JSON (see file tmpfile2)"
	    exit
	fi
    else
	echo "failed: pcap2flow internal failure (see file tmpfile)"
	exit
    fi
done

echo "all tests passed"

rm -f tmpfile tmpfile2


