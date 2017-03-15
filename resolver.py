"""
Python program to resolve a domain name or mail server to ip
by quering a list of root DNS servers, then subsequently quering
lists of servers until the answer response to the query is found.

Author: Ryan T. DeMuse
Date: 6 March 2015
"""

import sys, struct, socket
from sys import argv
from struct import *


"""
Convert the hostname string from human readable form 
to network DNS readable format.
@param string of hostname
"""
def stringToNetwork(string):
	ls = string.split(".")
	ret = ""
	for tok in ls:
		formatString = "B"
		formatString += str(len(tok))
		formatString += "s"
		ret += pack(formatString,len(tok),tok)
	ret += pack("B",0)
	return ret


"""
Function to convert a network style string to a human
readable style string. Credit to Dr. Sat for giving 
us this very useful function.
@param response from network query
@param starting position of string to convert
"""
def networkToString(response,start):
	toReturn = ""
	position = start
	length = -1
	while True:
		length = unpack("!B",response[position])[0]
		if length == 0:
			position += 1
			break
		# Handle DNS pointers
		elif (length & 1 << 7) and (length & 1 << 6):
			b2 = unpack("!B",response[position+1])[0]
			offset = 0
			for i in range(6):
				offset += (length & 1 << i)
			for i in range(8):
				offset += (b2 & 1 << i)
			dereferenced = networkToString(response,offset)[0]
			return toReturn + dereferenced, position + 2
		formatString = str(length) + "s"
		position += 1
		toReturn += unpack(formatString,response[position:position+length])[0]
		toReturn += "."
		position += length
	return toReturn[:-1], position

"""
Construct the query to send to the DNS servers to 
determine a hostname IP address
@param ID of query
@param hostname to resolve
@param mflag = 0 if website 1 if mail server
"""
def constructQuery(ID,hostname,mflag):
	flags, num_answers, num_auth, num_other, num_questions = 0, 0, 0, 0, 1
	header = pack("!HHHHHH", ID, flags, num_questions, num_answers, num_auth, num_other)
	qname = stringToNetwork(hostname)
	qtype = (15 if mflag else 1)
	remainder = pack("!HH",qtype,1)
	return (header+qname+remainder)


"""
Recursively query a list of servers to resolve
the ip address of hostname 
@param list of servers
@param the query to send to the servers, constructed using constructQuery()
@param hostname to resolve
@param 1 if mail server 0 if website
"""
def iterativeQuery(serv_list,query,sock,hostname,mflag):
	ipAnswer = hostname
	type = 0
	for ip in serv_list:
		response = None
		try:
			sock.sendto(query,(ip,53))
			tuple = (ip,"mail exchange" if mflag else "name",hostname)
			print "\nQuering %s for DNS of %s %s..." % tuple
			(response,(address,port)) = sock.recvfrom(4096)
			(serv_list,ans,ipAnswer,type,tuple) = handleQuery(response,query,mflag)
			print "Received %d Answers, %d Authoritative Answers, and %d Additional Answers.\n" % tuple
			if tuple[2] > 0 and tuple[0] == 0:
				ipAnswer, type = iterativeQuery(serv_list,query,sock,hostname,mflag)
				break
			else:
				break
			return ipAnswer, type
		except socket.timeout as e:
			print "Connection to", ip, "timed out."
			print "Exception:", e
	return ipAnswer, type



"""
Handle the iterative query process to try to
process the query response.
@param the query response
@param the query itself
@param mail server or website
"""
def handleQuery(response,query,mflag):
	auth_serv_list = []
	ans = 0
	ipAnswer, type, tuple = None, None, None
	if response is not None:
		checkValidHostname(response)
		(quest,ans,auth,addit) = unpack("!HHHH",response[0x2e-0x2a:0x36-0x2a])
		tuple = (ans,auth,addit)
        q_size = sys.getsizeof(query) + 5 - 0x2a
        if tuple[0] > 0:
			ipAnswer, type = answerFound(q_size,response,mflag)
        else:
			q_size = authAnswers(auth,q_size,response)
			q_size,auth_serv_list = additAnswers(addit,q_size,response)
	return auth_serv_list,ans,ipAnswer,type,tuple



"""
Determine if the given hostname is valid.
Exit if the hostname is not real
"""
def checkValidHostname(response):
	flags = unpack("!B",response[0x2d-0x2a])[0]
	if flags == 0x3:
		print "\nInvalid hostname. Name could not be resolved.\nExiting...\n"
		sys.exit(1)



"""
Parse through the authoritative answer section
of the answer sections.
@param num auth answers
@param location in response
@param response of query
"""
def authAnswers(auth,q_size,response):
	for j in range(auth):
		q_size += 10
		data_len = unpack("!H",response[q_size:q_size+2])[0]
		q_size += (2+data_len)
	return q_size



"""
Parse through the additional answer section
of the answer sections of the the query response.
@param num addit answers
@param location in response
@param response of query
"""
def additAnswers(addit,q_size,response):
	ipaddrs = []
	for k in range(addit):
		q_size += 2
		type = unpack("!H",response[q_size:q_size+2])[0]
		q_size += 8
		data_len = unpack("!H",response[q_size:q_size+2])[0]
		q_size += 2
		addr = unpack("!BBBB",response[q_size:q_size+4])
		if type == 1:
			ipaddrs.append('.'.join(str(x) for x in addr))
		q_size += 4
	return q_size, ipaddrs



"""
Determine what to do what answer is found and
return the ip address of the hostname originally
queried.
@param location in reponse
@param response of query
@param mail server or website
"""
def answerFound(q_size,response,mflag):
	if not mflag:
		q_size += 2
		type = unpack("!H",response[q_size:q_size+2])[0]
		if type == 1:
			q_size += 10
			addr = unpack("!BBBB",response[q_size:q_size+4])
			ipaddr = '.'.join(str(x) for x in addr)
		else:
			q_size += 10
			ipaddr = networkToString(response,q_size)[0]
		return ipaddr, type
	else:
		q_size += 2
		type = unpack("!H",response[q_size:q_size+2])[0]
		q_size += 8
		data_len = unpack("!H",response[q_size:q_size+2])[0]
		q_size += 4
		exchange = networkToString(response,q_size)
		return exchange[0], type



"""
Extract the root server ip addresses from the
root-servers.txt file
@param "root-servers.txt"
"""
def parseDNSFile(file):
	return [ip.rstrip() for ip in open(file,"r").readlines()]



"""
Main program to control the quering of servers.
"""
def main(argv):
	mflag = 0
	hostname = argv[1]
	if argv[1] == "-m":
		mflag = 1
		hostname = argv[2]
	sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
	sock.settimeout(10)
	query = constructQuery(5,hostname,mflag)
	dns_serv_list = parseDNSFile("root-servers.txt")
	print "\n\nBeginning query of root servers...\n"
	while 1:
		ipAddress, type = iterativeQuery(dns_serv_list,query,sock,hostname,mflag)
		query = constructQuery(5,ipAddress,0)
		mflag = 0
		if type == 1:
			break
	print "\nHostname Resolved.\n%s resolves to: %s\n" % (hostname,ipAddress)
	return "dif tor heh smusma leonard nimoy"



if __name__ == '__main__':
	main(argv)


