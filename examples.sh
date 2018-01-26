# examples.sh
#
# examples for running the sleuth program
#
# usage:    bash -x examples.sh file1 [file2 ...]

# quick documentation for sleuth
#
# The sleuth program reads a stream of flow objects, processes each one
# in sequence, and writes out the resulting objects.  There are several
# processing stages, each of which is optional; their order is:
#
#    Filtering objects (--where)
#    Selecting elements (--select)
#    Splitting into multiple output streams (--groupby)
#    Computing the distribution (--dist)
#    Computing the sum of particular elements (--sum)
#
#
# The --where, --select, and --groupby commands use pseudo-JSON notation
# to specify JSON objects of interest.  A pseudo-JSON expression is
# formed from a JSON expression by removing the quotes around each
# name, removing each value, and removing colons.  For instance, the
# pseudo-JSON expression
#
#    sp,dp,tcp{out{opts[{mss}]}}}
#
# matches the JSON object
#
#    {"sp":65150, "dp":443, "tcp":{"out":{"opts":[{"mss":1460}]}}}
#
# In a manner of speaking, a pseudo-JSON object looks like the JSON
# objects it matches, with the values stripped out.  Pseudo-JSON
# command line arguments should be enclosed in quotes, so that any
# commas that appear in those arguments do not confuse the shell.
# That is, the argument --select "sa,da,sp,dp,pr" should work with
# your shell, wheras --select sa,da,sp,dp,pr may not.
#
#
# The --pretty command causes the JSON output to be pretty-printted,
# in which case there is a single JSON element on each line, with
# indentation to promote readability.
#
#
# Normally, sleuth stitches together successive flow objects with the
# same flow key.  The --no_stitch command prevents this stitching from
# taking place.  This option should not normally be used; otherwise, a
# single long-lived flow might appear to be a succession of flows, and
# this situation may create ambiguity about flow direction.
# 
#
# The --select command selects particular elements to be included in
# the objects; all other elements are excluded.  The order of the
# objects is unchanged.  The syntax is:
#
# --select <elementlist>
# 
#   <elementlist> = <element>
#                   OR <elementlist> , <element>
# 
#   <element> = pseudo-JSON expresson, like "bytes_out" or
#               "packets[{b}]" or "http[{in[{Content-Type}]}]"
# 
#
#
# The --where command filters objects against a condition, so that the
# condition is true for each object output.  The order of the objects
# is unchanged.  The syntax is:
#
# --where <condition>
# 
#   <condition> = <predicate> 
#                 OR '(' <predicate> ')' 
#                 OR <predicate> '|' <predicate>   # or (disjuntion)
#      	          OR <predicate> ',' <predicate>   # and (conjunction)
#  
#   <predicate> = <element> <operator> <value>
# 
#   <operator>  = '='       # equals 
#                 OR '~'    # not equals
#                 OR '>'    # greater than (numbers only)
#                 OR '<'    # less than (numbers only)
# 
#   <value>     = <characterstring> 
#                 OR <number>
# 
#   <element>   = as above 
#
# The condition <element>=* is true whenever <element> is present in
# an object, and <element>~* is true whenever <element> is not present
# in an object.  The 'wildcard' values '*' and '?' can be included in
# character strings (one or more times), in which case '*' matches any
# sequence of characters and '?' matches any single character.  If
# <element> includes an array, then its predicate is true if it holds
# for any value in the array.  For instance, --where
# "http[{in[{Content-Type}]}]=*xml" matches any HTTP Content-Type that
# ends in "xml".
#
# The command --dist computes the distribution of the objects, and
# counts the number of times that each object appears in the stream,
# as well as the total number of objects; elements representing those
# sums are included in the output stream as "count" and "total",
# respectively.  The order of the objects may be changed.  The --dist
# command does not have any arguments.
#
# The --dist command is currently a memory hog, and it might fail on
# very large data inputs.
# 
#
# The --groupby command splits the input stream into one or more
# output streams, grouped by one or more elements.  The output order
# of the objects may be different than the input order.  The syntax
# is:
#
# --groupby <elementlist> 
#
# For each value of the elements in <elementlist>, a separate output
# stream is created.  The downstream processing is performed
# separately on each of those output streams.  For instance: 
#
#  '--groupby da' creates a separate stream for each destination address
#
#  '--groupby da,dp' creates a stream for each distinct (destination
#  address, destination port) tuple
#
# The --groupby command is currently a memory hog, and it might fail on
# very large data inputs.
#
#
# The command --sum computes the sum, across all objects, of one or more
# elements.  The order of the objects may be changed.  The syntax is:
#
# --sum <elementlist> 
#
# For each <element> in the argument, the value of that element from
# each object in the stream is added into a tally, which is written
# into an output object as the value of that element.  The <elements>
# list must contain at least one element, and may contain multiple
# elements.  The other elements in the object SHOULD be constant.
# 
# 

# show flows that contain a packet whose payload is exactly 50 bytes in length
#
./sleuth $@ --where "packets[{b}]=50" --select "da,packets[{b}]" 


# for flows containing interpacket times greater than 1000ms, show the
# destination address as well as the inter-packet timings and
# direction
#
./sleuth $@ --where "packets[{ipt}]>1000" --select "da,packets[{ipt,dir}]" 


# for flows whose outbound bytes exceed 10,000, show the protocol,
# destination port, destination address, and the number of outbound
# bytes
#
./sleuth $@ --where "bytes_out>10000" --select "pr,dp,da,bytes_out"


# show TCP traffic other than HTTP; use tcp=* to detect flows for
# which a TCP handshake was observed, instead of pr=6, because in the
# latter case the directionality might be confused
#
./sleuth $@ --where "tcp=*,dp~80" --select pr,dp,da 


# show flows destined to internal addresses
#
./sleuth $@ --select "sa,sp,da,dp,pr" --where "da=10.*|da=192.168.*"


# show traffic with byte entropy over four, if it is not HTTP or HTTPS
#
./sleuth $@ --where "entropy>4,dp~80,dp~443" --select dp,bytes_out,entropy 


# what addresses are the top destinations to which data has been sent?  show
# the sum of bytes_out across all flows grouped by destination address
#
./sleuth $@ --select "da,bytes_out" --groupby da --sum bytes_out | sort -k 2 -nr

# show the distribution of HTTP User-Agent and Accept-Encoding headers
#
./sleuth $@ --select "http[{out[{User-Agent,Accept-Encoding}]}]"  --dist

# show the HTTP response body for flows in which Content-Encoding does
# not appear, and byte entropy > 7
#
./sleuth $@ --select "http[{in[{body,Content-Type}]}],entropy" --where "dp=80,entropy>6" 

# show tls client fingerprints and destination addresses, using
# --where tls=* so that only tls flows get reported
#
./sleuth $@ --where tls=* --fingerprint tls --select inferences,da 
# {"inferences": {"tls": ["firefox-31.0"]}, "da": "63.245.216.134"}
# {"inferences": {"tls": ["firefox-31.0"]}, "da": "63.245.217.161"}
# {"inferences": {"tls": ["firefox-31.0"]}, "da": "63.245.217.161"}
# {"inferences": {"tls": ["firefox-58.0"]}, "da": "172.217.12.238"}
# {"inferences": {"tls": ["firefox-58.0"]}, "da": "216.58.217.78"}

# show the linked DNS request names for TLS sessions with client
# fingerprints matching firefox-58
#
./sleuth $@ --fingerprint tls  --where "inferences{tls[]}=firefox-58*"  --select linked_dns{dns[{rn}]}
# {"linked_dns": {"dns": [{"rn": "google.com"}, {"rn": "google.com"}]}}
# {"linked_dns": {"dns": [{"rn": "getpocket.cdn.mozilla.net"}, {"rn": "getpocket.cdn.mozilla.net"}]}}
# {"linked_dns": {"dns": [{"rn": "tiles.services.mozilla.com"}, {"rn": "tiles.services.mozilla.com"}]}}
# {"linked_dns": {"dns": [{"rn": "www.google.com"}, {"rn": "www.google.com"}]}}


