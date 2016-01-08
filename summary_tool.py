from __future__ import division
import json
import math
from pprint import pprint
import argparse

#length_wrapper = []

# create a dictionary with protocol numbers
prDict = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP"}

# basic summary
def print_summary(length, data):
	# print number of flows
	#print length_wrapper[0]	
	print "\n{0:25} ==> {1:10.0f}".format("Number of flows: ", length)

	# calculate length of messages
	#messageInbound = list()
	#messageOutbound = list()
	messageTotal = list()

	for i in range(length):
		mIn = 0
		mOut = 0
		if data["appflows"][i]["flow"].get("ib") is not None:
			mIn = data["appflows"][i]["flow"]["ib"]
		
		if data["appflows"][i]["flow"].get("ob") is not None:
			mOut = data["appflows"][i]["flow"]["ob"]	
	
		#messageInbound.append(mIn)	
		#messageOutbound.append(mOut)
		messageTotal.append(mIn + mOut)

		#sortedInbound = sorted(messageInbound)
		#sortedOutbound = sorted(messageOutbound)
		sortedTotal = sorted(messageTotal)

	#print "Max message length (inbound): ", sortedInbound[length-1]
	#print "Max message length (outbound): ", sortedOutbound[length-1]
	print "\n{0:25} ==> {1:10.0f}".format("Max message length:", sortedTotal[length-1])

	#aveIn = sum(sortedInbound) / length
	#aveOut = sum(sortedOutbound) / length
	aveTot = sum(sortedTotal) / length

	#print "Ave message length (inbound): ", aveIn
	#print "Ave message length (outbound): ", aveOut
	print "{0:25} ==> {1:10.0f}".format("Ave message length:", aveTot)

	devIn = 0
	devOut = 0
	devTot = 0

	#for i in sortedInbound:
	#	devIn += pow(i - aveIn, 2)

	#for i in sortedOutbound:
	#	devOut += pow(i - aveOut, 2)

	for i in sortedTotal:
		devTot += pow(i - aveTot, 2)

	#print "Std dev of a message (inbound): ", math.sqrt(devIn / length)
	#print "Std dev of a message (outbound): ", math.sqrt(devOut / length)
	print "{0:25} ==> {1:10.2f}".format("Std dev of a message:", math.sqrt(devTot / length))

# print summary of any additional fields
def print_extra(field, length, data):
	field_list = list()
	for i in range(length):
		field_list.append(data["appflows"][i]["flow"].get(field))

	field_set = set(field_list)
	field_set_sorted = sorted(field_set)
	print "\nSummary for", field, ":"
	for item in field_set_sorted:
		field_occur = field_list.count(item)*100/length
		print "{0:25} ==> {1:10.2f}".format(item, field_occur) + "%"

#beList = list()
#for i in range(length):
	#if data["appflows"][i]["flow"].get("be") is not None: 
#	beList.append(data["appflows"][i]["flow"].get("be"))

#beSet = set(beList)
#for item in beSet:
#	beOccur = beList.count(item)*100/length
#	print "{0:10} ==> {1:10.2f}".format(item, beOccur) + "%"



# create a list of 'sa', 'pr' fields (source address, protocols) and count the outbound, inbound
#saList = list()
#for i in range(length):
#	saList.append(data["appflows"][i]["flow"].get("dp"))

# source addresses
#saSet = set(saList)
#saSet = sorted(saSet)
#for item in saSet:
#	saOccur = saList.count(item)*100/length
	#print "{0:10} ==> {1:10.2f}".format(item, saOccur) + "%"

# create a list of 'pr' fields (protocols)
#prList = list()
#for i in range(length):
#	prList.append(data["appflows"][i]["flow"]["pr"])

# print percentages of destination protocols
#prSet = set(prList)
#for item in prSet:
#	prOccur = prList.count(item)*100/length
	#print "{0:10} ==> {1:10.2f}".format(prDict[item], prOccur)+"%"

# main funciton
def main():
	# parse command line arguments
	parser = argparse.ArgumentParser()
	parser.add_argument("-ifolder", help = "specify path to folder with flows")
	parser.add_argument("-ifield", help = "specify any additional fields for the summary program, must be separated by spaces")

	args = parser.parse_args()

	if args.ifolder:
		# read in a file
		with open(args.ifolder) as data_file:
			data = json.load(data_file)

	# length of a file
	length = len(data["appflows"])
	#length_wrapper = [length]

	#print length_wrapper[0]
	print_summary(length, data)
	
	if args.ifield:
		fields = str.split(args.ifield)
		for item in fields:
			print_extra(item, length, data)
	
if __name__ == "__main__":
	main()
