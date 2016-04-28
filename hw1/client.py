import struct
import socket
from uuid import getnode as get_mac
from random import randint

serverName = '255.255.255.255'
serverPort = 67
addr = (serverName,serverPort)
clientport = 68
clientSocket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
clientSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
clientSocket.bind(('',clientport))

#DHCP_DISCOVER message
print ("send DISCOVER message")
OP = b'\x01'
HTYPE = b'\x01'
HLEN = b'\x06'
HOPS = b'\x00'

transactionID = b''
for i in range(4):
    t = randint(0, 255)
    transactionID += struct.pack('!B', t)
TRANSACTION_ID = transactionID
SECS = b'\x00\x00'
FLAGS = b'\x00\x00'
CIADDR = b'\x00\x00\x00\x00'
YIADDR = b'\x00\x00\x00\x00'
SIADDR = b'\x00\x00\x00\x00'
GIADDR = b'\x00\x00\x00\x00'

macb = b''
mac = str('%012X' % get_mac())
for i in range(0, 12, 2):
    s = int(mac[i:i + 2], 16)
    macb += struct.pack('B',s)
CHADDR = macb
CHADDR += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

SNAME = b'\x00' * 64
FILE = b'\x00' * 128

Magic_Cookie = b'\x63\x82\x53\x63'

Option =  b'\x35\x01\x01' #53 discover
Option += b'\x3d\x06' + macb #61 Client-identifier
Option += b'\x37\x03\x03\x01\x06'   #55 Parameter Request List
Option += b'\xff' 

sendDiscoverList = OP+HTYPE+HLEN+HOPS+TRANSACTION_ID+SECS+FLAGS+CIADDR+YIADDR+SIADDR+GIADDR+CHADDR+SNAME+FILE+Magic_Cookie+Option
clientSocket.sendto(sendDiscoverList,addr)


#receive Offer message
print ("receive Offer message")
clientSocket.settimeout(20)

while 1:
    
    Data = clientSocket.recv(2048)
    #type = int(Data[242])
    #serverip = socket.inet_aton(socket.gethostbyname(socket.gethostname()))
    
    if  Data[4:8]==TRANSACTION_ID:
        TransID = Data[4:8]     
        NextServerIP = Data[20:24]
        MACaddr = Data[28:34]
        DHCPServerIdentifier = Data[245:249]
        offerIP = Data[16:20]

        #DHCP_REQUEST message
        print ("send REQUEST message")
        OP = b'\x01'
        HTYPE = b'\x01'
        HLEN = b'\x06'
        HOPS = b'\x00'
        TRANSACTION_ID = TransID
        SECS = b'\x00\x00'
        FLAGS = b'\x00\x00'
        CIADDR = b'\x00\x00\x00\x00'
        YIADDR = b'\x00\x00\x00\x00'
        SIADDR = b'\x00\x00\x00\x00'
        GIADDR = b'\x00\x00\x00\x00'

        CHADDR = MACaddr    
        CHADDR += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'


        SNAME = b'\x00' * 64
        FILE = b'\x00' * 128
        Magic_Cookie = b'\x63\x82\x53\x63'
        Option =  b'\x35\x01\x03' #(53) DHCP Message Type (Request)
        Option += b'\x32\x04' + offerIP #(50) request
        Option += b'\x36\x04' + DHCPServerIdentifier  #(54) DHCP Server Identifier
        #Option += b'\x3d\x07\x01' + CHADDR #61: Client identifier
        Option += b'\xff' #end

        sendRequestList = OP+HTYPE+HLEN+HOPS+TRANSACTION_ID+SECS+FLAGS+CIADDR+YIADDR+SIADDR+GIADDR+CHADDR+SNAME+FILE+Magic_Cookie+Option
        clientSocket.sendto(sendRequestList,addr)

        #receive ACK message
    
        #print "receive ACK message"
        clientSocket.settimeout(2)
        

    AckData = clientSocket.recv(2048)
    if AckData[4:8]==TRANSACTION_ID:
        print("receive ACK message")

        print("OP: "+AckData[0].encode('hex'))
        print('HTYPE: '+AckData[1].encode('hex'))
        print('HLEN: '+AckData[2].encode('hex'))
        print('HOPS: '+AckData[3].encode('hex'))
        print('TRANSACTION_ID: '+AckData[4:8].encode('hex'))
        print('SECS: '+AckData[8:10].encode('hex'))
        print('FLAGS: '+AckData[10:12].encode('hex'))
        print('CIADDR: '+AckData[12:16].encode('hex'))
        print('YIADDR: '+AckData[16:20].encode('hex'))
        print('SIADDR: '+AckData[20:24].encode('hex'))
        print('GIADDR: '+AckData[24:28].encode('hex'))
        print('CHADDR(+ padding): '+AckData[28:44].encode('hex'))
        print('SNAME: '+AckData[44:108].encode('hex'))
        print('FILE: '+AckData[108:236].encode('hex'))
        print('Magic_Cookie: '+AckData[236:240].encode('hex'))
        print('Option:') #34
        print('Option(53): '+AckData[240:243].encode('hex')) #ACK
        print('Option(54): '+AckData[243:249].encode('hex')) #Server Identifier
        print('Option(51): '+AckData[249:255].encode('hex')) # Lease Time
        print('Option(3): '+AckData[255:261].encode('hex'))  #Router
        print('Option(1): '+AckData[261:267].encode('hex'))  #Subnet Mask
        print('Option(6): '+AckData[267:273].encode('hex'))  #Domain Name Server
        print('Option(END): '+AckData[273].encode('hex'))
        break
    

clientSocket.close()
