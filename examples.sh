# examples.sh
#
# examples for running the joyq program 

# quick documentation for joyq
#
# The joyq program reads a stream of flow objects, processes each one
# in sequence, and writes out the resulting objects.  There are several
# processing stages, each of which is optional; their order is:
#
#    Filtering objects (--where)
#    Selecting elements (--select)
#    Splitting into multiple output streams (--split)
#    Computing the distribution (--dist)
#    Computing the sum of particular elements (--sum)
#
# The --pretty command causes the JSON output to be pretty-printted,
# in which case there is a single JSON element on each line, with
# indentation to promote readability.
#
#
# The --stitch command causes flow objects to be stitched together;
# this option SHOULD always be used with flow data; otherwise, a
# single long-lived flow might appear to be a succession of flows, and
# this situation creates ambiguity about flow direction.
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
#   <element> = pseudo-JSON expresson, like "ob" or "packets[{b}]" or
#               "ohttp{Content-Encoding}"
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
# <element> is an array, then its predicate is true if it holds for
# any value in the array.
#
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
# The --split command splits the input stream into one or more output
# streams, indexed by one or more elements.  The output order of the
# objects may be different than the input order.  The syntax is:
#
# --split <elementlist> 
#
# For each value of the elements in <elementlist>, a separate output
# stream is created.  The downstream processing is performed
# separately on each of those output streams.  For instance: 
#
#  '--split da' creates a separate stream for each destination address
#
#  '--split da,dp' creates a stream for each distinct (destination
#  address, destination port) tuple
#
# The --split command is currently a memory hog, and it might fail on
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
cat sjc24.json | ./joyq --stitch  --where "packets[{b}]=50" --select "da,packets[{b}]" 
#
# {"packets": [{"b": 50}, {"b": 116}], "da": "171.70.168.183"}
# {"packets": [{"b": 50}, {"b": 451}], "da": "171.70.168.183"}
# {"packets": [{"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}, {"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}], "da": "10.32.222.255"}
# {"packets": [{"b": 50}, {"b": 50}, {"b": 50}], "da": "10.41.35.255"}
# {"packets": [{"b": 50}, {"b": 50}, {"b": 50}, {"b": 50}, {"b": 50}, {"b": 50}, {"b": 50}], "da": "10.41.35.255"}

# for flows containing interpacket times greater than 1000ms, show the
# destination address as well as the inter-packet timings and
# direction
#
cat sjc24.json | ./joyq --stitch  --where "packets[{ipt}]>1000" --select "da,packets[{ipt,dir}]" 
#
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1023, "dir": "<"}], "da": "10.32.222.255"}
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1084, "dir": "<"}], "da": "224.0.0.251"}
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1755, "dir": "<"}, {"ipt": 1416, "dir": "<"}], "da": "10.41.35.255"}


# for flows whose outbound bytes exceed 10,000, show the protocol,
# destination port, destination address, and the number of outbound
# bytes
#
cat sjc24.json | ./joyq --stitch  --where "ob>10000" --select pr,dp,da,ob
#
# {"pr": 6, "ob": 16885, "dp": 80, "da": "23.72.195.113"}
# {"pr": 6, "ob": 12933, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 16360, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 16703, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 14580, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 20728, "dp": 80, "da": "104.95.110.78"}


# show TCP traffic other than HTTP and HTTPS
#
cat sjc24.json | ./joyq --stitch --where "pr=6,(dp~80,dp~443)" --select pr,dp,da 
#
# {"pr": 6, "dp": 58615, "da": "10.41.32.146"}
# {"pr": 6, "dp": 58639, "da": "10.41.32.146"}
# {"pr": 6, "dp": 59494, "da": "10.41.32.146"}
# {"pr": 6, "dp": 5060, "da": "171.70.146.227"}
# {"pr": 6, "dp": 5060, "da": "173.36.131.167"}
# {"pr": 6, "dp": 4001, "da": "69.46.36.10"}
# {"pr": 6, "dp": 59641, "da": "10.41.32.146"}
# {"pr": 6, "dp": 59640, "da": "10.41.32.146"}
# {"pr": 6, "dp": 58361, "da": "10.41.32.146"}
# {"pr": 6, "dp": 58362, "da": "10.41.32.146"}
# {"pr": 6, "dp": 59638, "da": "10.41.32.146"}

# show flows destined to internal addresses
#
cat sjc24.json | ./joyq --stitch --select "sa,sp,da,dp" --where "da=10.*|da=192.168.*"
#
# {"sa": "10.41.35.87", "sp": 61031, "dp": 8612, "da": "10.41.35.255"}
# {"sa": "10.41.35.203", "sp": 137, "dp": 137, "da": "10.41.35.255"}
# {"sa": "10.41.33.92", "sp": 58265, "dp": 8612, "da": "10.41.35.255"}
# {"sa": "10.32.222.70", "sp": 58456, "dp": 8612, "da": "10.32.222.255"}
# {"sa": "10.41.32.107", "sp": 137, "dp": 137, "da": "10.41.35.255"}
# {"sa": "10.41.32.88", "sp": 63487, "dp": 8612, "da": "10.41.35.255"}


# show traffic with byte entropy over six, if it is not HTTP or HTTPS
#
cat sjc24.json | ./joyq --stitch --where "be>6,(dp~80,dp~443)" --select da,be,ob 
#
# {"be": 7.951398, "ob": 6327, "da": "10.41.32.146"}
# {"be": 7.845978, "ob": 1295, "da": "10.41.32.146"}

# what addresses are the top destinations to which data has been sent?
#
cat sjc24.json | ./joyq --stitch --select "da,ob" --split da --sum ob | sort -k 4 -n
#
# {"sum_over": 3, "ob": 6917, "da": "52.21.39.34"}
# {"sum_over": 6, "ob": 7183, "da": "74.119.117.74"}
# {"sum_over": 6, "ob": 7325, "da": "104.95.208.83"}
# {"sum_over": 4, "ob": 8609, "da": "151.101.192.68"}
# {"sum_over": 7, "ob": 9485, "da": "192.82.210.130"}
# {"sum_over": 34, "ob": 12882, "da": "255.255.255.255"}
# {"sum_over": 9, "ob": 15276, "da": "54.230.141.63"}
# {"sum_over": 99, "ob": 18385, "da": "10.32.222.255"}
# {"sum_over": 7, "ob": 24261, "da": "74.119.117.78"}
# {"sum_over": 650, "ob": 26752, "da": "171.70.168.183"}
# {"sum_over": 9, "ob": 27551, "da": "54.192.143.240"}
# {"sum_over": 5, "ob": 28071, "da": "74.119.117.94"}
# {"sum_over": 7, "ob": 31900, "da": "52.44.230.168"}
# {"sum_over": 257, "ob": 44536, "da": "10.41.35.255"}
# {"sum_over": 6, "ob": 78295, "da": "104.95.110.78"}
# {"sum_over": 235, "ob": 99729, "da": "224.0.0.251"}
# {"sum_over": 11, "ob": 112653, "da": "23.72.195.113"}

# show the distribution of HTTP User-Agent and Accept-Encoding headers
#
cat sjc24.json | ./joyq --stitch --select "ohttp{User-Agent,Accept-Encoding}"  --dist
# {"count": 94, "ohttp": {"Accept-Encoding": "gzip, deflate", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50"}, "total": 115}
# {"count": 17, "ohttp": {"Accept-Encoding": "gzip, deflate"}, "total": 115}
# {"count": 3, "ohttp": {"Accept-Encoding": "identity", "User-Agent": "AppleCoreMedia/1.0.0.15G1004 (Macintosh; U; Intel Mac OS X 10_11_6; en_us)"}, "total": 115}
# {"count": 1, "ohttp": {"Accept-Encoding": "gzip, deflate", "User-Agent": "ocspd/1.0.3"}, "total": 115}

# show the HTTP response body for flows in which Content-Encoding does
# not appear, and byte entropy > 7
#
cat sjc24.json | ./joyq --stitch --select "ihttp{body}" --where "be>7,ihttp{Content-Encoding}~*" 
# {"ihttp": {"body": "2e89504e470d0a1a0a0000000d4948445200"}}
# {"ihttp": {"body": "2effd8ffe000104a46494600010101012c01"}}
# {"ihttp": {"body": "2e89504e470d0a1a0a0000000d4948445200"}}
# {"ihttp": {"body": "2e89504e470d0a1a0a0000000d4948445200"}}


# negative test; this run should fail
#
cat sjc24.json | ./joyq --stitch --select "da,ob" --where "be>>>>>9|"
