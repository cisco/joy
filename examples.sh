# examples.sh
#
# examples for running the joyq program 


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

cat sjc24.json | ./joyq --stitch  --where "packets[{ipt}]>1000" --select "da,packets[{ipt,dir}]" 
#
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1023, "dir": "<"}], "da": "10.32.222.255"}
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1084, "dir": "<"}], "da": "224.0.0.251"}
# {"packets": [{"ipt": 0, "dir": "<"}, {"ipt": 1755, "dir": "<"}, {"ipt": 1416, "dir": "<"}], "da": "10.41.35.255"}


cat sjc24.json | ./joyq --stitch  --where "ob>10000" --select pr,dp,da,ob
#
# {"pr": 6, "ob": 16885, "dp": 80, "da": "23.72.195.113"}
# {"pr": 6, "ob": 12933, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 16360, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 16703, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 14580, "dp": 80, "da": "104.95.110.78"}
# {"pr": 6, "ob": 20728, "dp": 80, "da": "104.95.110.78"}


# TCP traffic other than HTTP and HTTPS
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


# traffic with byte entropy over six, but not HTTP or HTTPS
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


cat sjc24.json | ./joyq --stitch --select "ohttp{User-Agent,Accept-Encoding}"  --dist
# {"count": 94, "ohttp": {"Accept-Encoding": "gzip, deflate", "User-Agent": "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_11_6) AppleWebKit/602.1.50 (KHTML, like Gecko) Version/10.0 Safari/602.1.50"}, "total": 115}
# {"count": 17, "ohttp": {"Accept-Encoding": "gzip, deflate"}, "total": 115}
# {"count": 3, "ohttp": {"Accept-Encoding": "identity", "User-Agent": "AppleCoreMedia/1.0.0.15G1004 (Macintosh; U; Intel Mac OS X 10_11_6; en_us)"}, "total": 115}
# {"count": 1, "ohttp": {"Accept-Encoding": "gzip, deflate", "User-Agent": "ocspd/1.0.3"}, "total": 115}



# negative test; this run should fail
#
cat sjc24.json | ./joyq --stitch --select "da,ob" --where "be>>>>>9|"
