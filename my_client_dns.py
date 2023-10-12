import random
import sys
import socket
from ast import literal_eval
def createDNSQuery(url):
    header_id = getID()
    header_flag = "0100"    #Set RD = 1, rest is 0
    header_question = "0001"    #One hostname at a time
    header_answer = "0000"
    header_auth = "0000"
    header_add = "0000"

	# a. Create and print the DNS header [15 pts]
    header = bytes.fromhex(header_id+header_flag+header_question+header_answer+header_auth+header_add)

	# b. Create and print the Question section [15 pts]
    question = bytes.fromhex(parseQN(url)+"0001"+"0001")

	# c. Print the entire query after converting to Hex [15 pts]
    return header + question, len(header.hex()), len(question.hex())

def parseQN(url):
    temp = url.split('.')
    ret = ''
    for x in temp:
        tempX = len(x)
        tempX = hex(tempX)
        ret += '0'+tempX.replace(tempX[:2], '')
        for y in x:
           val = (hex(ord(y))) 
           hexCutTwo = val.replace(val[:2], '') 
           ret+=hexCutTwo
    ret+="00"

    return ret



def getID():
    rand = random.randint(0, 0xffff)
    ret = hex(rand)
    ret = ret.replace(ret[:2], '')
    if(len(ret)==3):
        ret= "0"+ret
    print(ret)
    return(ret)


def sendDNSQuery(query):
    primary_DNS = "8.8.4.4"
    port = 53
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) #UDP connection
    udp_socket.sendto(query, (primary_DNS, port))
    return udp_socket

def receiveDNSQuery(sock):
    max_attempts = 3
    sock.settimeout(5)
    count = 1
    for x in range(max_attempts):
        try:
            data, addr = sock.recvfrom(1024)
            if(len(data)>0):
                print("DNS Response received (attempt ", count, " of 3)\n")
                #print("Received message: %s" % data)
                break
        except socket.timeout:
            print("Timed out (attempt : ", count, ")")
            if count == max_attempts:
                print("Max attempts reached: No response received")
            else:
                print("Retrying (attempt : ", count, ")")
        count+=1
    return data, addr

def printDNSResponse(data, addr, len_header, len_question):
    # a. Parse and print the response header [15 pts]
	# b. Print the resolved IP address [15 pts]
    print(len(data.hex()), len_header, len_question)
    data = data.hex()
    response_id = data[0:4]
    response_flag = data[4:8]
    response_question = data[8:12]
    response_answer = data[12:16]
    response_auth = data[16:20]
    response_add = data[20:24]

    response_qname = data[len_header: len_question+len_header-8]
    response_qtype = data[len_question+len_header-8: len_question+len_header-4]
    response_qclass = data[len_question+len_header-4: len_question+len_header]
    # print(response_qname)
    answer_rdata = data[len(data)-8: len(data)]
    answer_rname = data[len_question+len_header: len(data)-24]
    answer_rtype = data[len(data)-24: len(data)-22]

    answer = data[len_question+len_header: len(data)]
    

    print("\n-- Processing DNS response --\n")
    # print(response_id, response_flag, reponse_question, response_answer, response_auth, reponse_add)
    print("Header ID =", response_id)
    
    temp = hex(int.from_bytes(bytes.fromhex(response_flag), "big")&0x8000)
    print("Header QR =", literal_eval(hex(literal_eval(temp)>>15)))
    
    temp = hex(int.from_bytes(bytes.fromhex(response_flag), "big")&0x7800)
    print("Header OPCODE =", hex(literal_eval(temp)>>11))

    # header AA
    
    # header TC
    
    # header RD
    
    # header RA
    
    # header Z
    
    # header RCODE

    # header QDCOUNT
    temp = hex(int.from_bytes(bytes.fromhex(response_question), "big"))
    print("Header QDCOUNT =", hex(literal_eval(temp)))
    # header ANCOUNT
    temp = hex(int.from_bytes(bytes.fromhex(response_answer), "big"))
    print("Header ANCOUNT =", hex(literal_eval(temp)))
    # header NSCOUNT
    temp = hex(int.from_bytes(bytes.fromhex(response_auth), "big"))
    print("Header NSCOUNT =", hex(literal_eval(temp)))
    # header ARCOUNT
    temp = hex(int.from_bytes(bytes.fromhex(response_add), "big"))
    print("Header ARCOUNT =", hex(literal_eval(temp)),"\n")




    temp = hex(int.from_bytes(bytes.fromhex(response_qname), "big"))
    print("Question QNAME =", temp)

    temp = hex(int.from_bytes(bytes.fromhex(response_qtype), "big"))
    print("Question QTYPE =", literal_eval(temp))

    temp = hex(int.from_bytes(bytes.fromhex(response_qclass), "big"))
    print("Question QCLASS =", literal_eval(temp), "\n")

    # print(response_qname, response_qtype, response_qclass)




    temp = hex(int.from_bytes(bytes.fromhex(answer_rname), "big"))
    print("Answer RNAME =", temp)

    temp = hex(int.from_bytes(bytes.fromhex(answer_rtype), "big"))
    print("Answer RTYPE =", temp)
  
    temp = hex(int.from_bytes(bytes.fromhex(answer_rdata), "big"))
    print("Answer RDATA =", temp)

    print(hex(int.from_bytes(bytes.fromhex(data), "big")))

    # print(answer)
    # print(answer_rname, answer_rtype, answer_rdata)


    
        
    # print("Response ID =", response_id)
    # print("Response ID =", response_id)
    # print("Response ID =", response_id)


    # if literal_eval(temp)>0:
    #     print("Response QR = 1")
    # else:
    #     print("Response QR = 0")
    # temp = hex(int.from_bytes(bytes.fromhex(response_flag), "big")&0x7800)
    # if literal_eval(temp)>0:
    
    return 1

def main(url):

    # a. Create socket [5 pts]
	# b. Send the DNS query [5 pts]
	# c. Receive the DNS response [5 pts]
	# d. Close the socket [5 pts]

    query, len_header, len_question = createDNSQuery(url)
    print("Sending: ",query)

    udp_sock = sendDNSQuery(query)
    data, addr = receiveDNSQuery(udp_sock)
    udp_sock.close()
    print("Data is: ",  data)
    print("Addr is: ", addr)
    printDNSResponse(data, addr, len_header, len_question)
    return 1

main(sys.argv[1])