import socket
import struct
serverName = '255.255.255.255'
serverPort = 67
clientport = 68
addr = (serverName,clientport)
serverSocket = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
serverSocket.bind(('',serverPort))

Mac_list = []
num = 1
#get serverIP
ip = socket.gethostbyname(socket.gethostname())
packedIP = socket.inet_aton(ip) #32-bit packed binary format
IPdata = packedIP[0:4]
#Mac_list.append(ord(packedIP[3]))  #ord():unicode

while 1:
     Sdata = serverSocket.recv(2048)
     
     #receive Discover message
     print("receive DISCOVER message")
     TransID = Sdata[4:8]
     NextServerIP = socket.inet_aton(socket.gethostbyname(socket.gethostname()))     
     MACaddr = Sdata[28:34]
     
     #DHCP_OFFER message
     print("send Offer message")
     OP = b'\x02'     
     HTYPE = b'\x01'
     HLEN = b'\x06'
     HOPS = b'\x00'
     TRANSACTION_ID = TransID

     SECS = b'\x00\x00'
     FLAGS = b'\x00\x00'
     CIADDR = b'\x00\x00\x00\x00'

     if 150 + num in Mac_list:
          num = num + 1

     YIADDR = IPdata[0:3] + struct.pack('B',150 + num) # str
     Mac_list.append(150+num)
     Assign_IP = YIADDR
     num = num + 1

     SIADDR = NextServerIP
     GIADDR = b'\x00\x00\x00\x00'

     CHADDR = MACaddr
     CHADDR += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

     SNAME = b'\x00' * 64
     FILE = b'\x00' * 128
     Magic_Cookie = b'\x63\x82\x53\x63'
     Option = b'\x35\x01\x02' #53-Offer
     Option += b'\x36\x04' + packedIP #54 DHCPServerIdentifier
     Option += b'\x33\x04\x00\x00\x1a\x23' #51 Lease time
     Option += b'\x03\x04' + packedIP #3 router
     Option += b'\x01\x04\xff\xff\xff\x00' #1 subnet mask
     Option += b'\x06\x0c'  + socket.inet_aton('9.7.10.15') #6 DNS servername
     Option += socket.inet_aton('9.7.10.16')
     Option += socket.inet_aton('9.7.10.18')
     Option += b'\xff' #end

     sendOfferList = OP+HTYPE+HLEN+HOPS+TRANSACTION_ID+SECS+FLAGS+CIADDR+YIADDR+SIADDR+GIADDR+CHADDR+SNAME+FILE+Magic_Cookie+Option     
     serverSocket.sendto(sendOfferList,addr)
     

     while 1:
          #receive REQUEST message
          print("receive REQUEST message")
          AData = serverSocket.recv(2048)
          TransID = AData[4:8]          
          NextServerIP = AData[20:24]
          MACaddr = AData[28:34]
          DHCPServerIdentifier = AData[245:249]
               
          #DHCP_ACK message
          print("send ACK message")

          OP = b'\x02'
          HTYPE = b'\x01'
          HLEN = b'\x06'
          HOPS = b'\x00'
          TRANSACTION_ID = TransID

          SECS = b'\x00\x00'
          FLAGS = b'\x00\x00'
          CIADDR = b'\x00\x00\x00\x00'

          YIADDR = Assign_IP
          SIADDR = NextServerIP
          GIADDR = b'\x00\x00\x00\x00'

          CHADDR = MACaddr
          CHADDR += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

          SNAME = b'\x00' * 64
          FILE = b'\x00' * 128
          Magic_Cookie = b'\x63\x82\x53\x63'
          Option = b'\x35\x01\x05' #53-ACK
          Option += b'\x36\x04' + DHCPServerIdentifier #54
          Option += b'\x33\x04\x00\x00\x1a\x23' #51
          Option += b'\x03\x04' + packedIP #3
          Option += b'\x01\x04\xff\xff\xff\x00' #1
          Option += b'\x06\x0c' + socket.inet_aton('9.7.10.15')#6
          Option += socket.inet_aton('9.7.10.16')
          Option += socket.inet_aton('9.7.10.18')
          Option += b'\xff' #end

          sendACKList = OP+HTYPE+HLEN+HOPS+TRANSACTION_ID+SECS+FLAGS+CIADDR+YIADDR+SIADDR+GIADDR+CHADDR+SNAME+FILE+Magic_Cookie+Option
          serverSocket.sendto(sendACKList,addr)
          break
     
serverSocket.close()
