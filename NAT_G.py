import traceback
import sys
import socket
import struct
import colorama
from colorama import Fore, Back, Style

colorama.init(autoreset=True)
Yellow = Fore.YELLOW
Red = Fore.RED
Green = Fore.GREEN
Mag = Fore.MAGENTA
Cyan = Fore.CYAN
Blue = Fore.BLUE
Reset = Fore.RESET

banner = '''
000000___00000000000___00000000000000000000000___00000
00000/__/\\000000000/00/\\0000000000___00000000/00/\\0000
00000\\00\\:\\0000000/00/::\\00000000/00/\\000000/00/:/_000
000000\\00\\:\\00000/00/:/\\:\\000000/00/:/00000/00/:/0/\\00
00_____\\__\\:\\000/00/:/~/::\\0000/00/:/00000/00/:/_/::\\0
0/__/::::::::\\0/__/:/0/:/\\:\\00/00/::\\0000/__/:/__\\/\\:\\
0\\00\\:\\~~\\~~\\/0\\00\\:\\/:/__\\/0/__/:/\\:\\000\\00\\:\\0/~~/:/
00\\00\\:\\00~~~000\\00\\::/000000\\__\\/00\\:\\000\\00\\:\\00/:/0
000\\00\\:\\00000000\\00\\:\\00000000000\\00\\:\\000\\00\\:\\/:/00
0000\\00\\:\\00000000\\00\\:\\00000000000\\__\\/0000\\00\\::/000
00000\\__\\/000000000\\__\\/000000000000000000000\\__\\/0000

PROJECT BY:- HIMANSHU GOHITE
OCT , CSE(Cyber SECURITY)

'''

# (printing the banner here)
for i in range(len(banner)):
    if banner[i] == "0":
        print(f"{Cyan}{banner[i]}", end="")
    elif (banner[i]).upper() in "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789&:-,()":
        print(f"{Yellow}{banner[i]}",end="")
    else:
        print(f"{Red}{banner[i]}", end="")

def getMacAddr(myData):
    myMAC = "%.2x:%.2x:%.2x:%2x:%.2x:%.2x" % (myData[0], myData[1], myData[2], myData[3], myData[4], myData[5])
    return myMAC

try:
    mySocket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
except socket.error as msg:
    print("Socket could not be created. Error Code: " + str(msg.errno) + " Message: " + msg.strerror)
    sys.exit()

# Open the output file in write mode
output_file = "network_output.txt"

def save_output_to_file(output):
    with open(output_file, "a") as file:
        file.write(output + "\n")
try:
    while True:
        packet = mySocket.recvfrom(65565)
        myPacket = packet[0]
        # Separator
        separator = "-" * 100
        string0 =(f"{Green}{separator}")
        print(string0)
        output =string0
        myEthlength = 14
        myEthHeader = myPacket[:myEthlength]

        try:
            myEth = struct.unpack("!6s6sH", myEthHeader)
        except struct.error as e:
            print("Error unpacking Ethernet header:", e)
            continue  # Skip to the next iteration of the loop

        myEthProtocol = socket.ntohs(myEth[2])
        string8 = ("Destination MAC : " + Green + getMacAddr(myEth[0]) + Reset + " Source MAC :" + Green + getMacAddr(myEth[1]) + Reset + " Protocol : " + Green + str(myEthProtocol) + Reset)
        print(string8)
        output +=string8

        if myEthProtocol == 8:
            myIPHeader = myPacket[myEthlength:myEthlength + 20]
            iph = struct.unpack("!BBHHHBBH4s4s", myIPHeader)

            version_ihl = iph[0]
            version = version_ihl >> 4
            ihl = version_ihl & 0xF
            myIPHeaderLength = ihl * 4
            ttl = iph[5]
            protocol = iph[6]
            mySrcIP = socket.inet_ntoa(iph[8])
            myDstIP = socket.inet_ntoa(iph[9])

            string1 =("Version : " + Red + str(version) + Reset + " IP Header Length : " + Red + str(ihl) + Reset + " TTl : " + Red + str(ttl) + Reset + " Protocol : " + Red + str(protocol) + Reset)
            print(string1)
            output += string1

            if protocol == 6:
                t = myEthlength + myIPHeaderLength
                # Check if there is enough data for the TCP header
                if len(myPacket) < t + 20:
                    print("Not enough data for TCP header")
                    continue  # Skip to the next iteration of the loop
                myTCPHeader = myPacket[t:t + 20]
                tcph = struct.unpack("!HHLLBBHHH", myTCPHeader)
                mySrcPort = tcph[0]
                myDstPort = tcph[1]
                sequence = tcph[2]
                acknowledgement = tcph[3]
                doff_reserved = tcph[4]
                tcph_length = doff_reserved >> 4

                string2 =( Yellow + "TCP PACKET!! " + Reset + " Source Port : " + Mag + str(mySrcPort) + Reset + " Destination Port : " + Mag + str(myDstPort) + Reset + " Sequence Number : " + Mag + str(sequence) + Reset)
                print(string2)
                output +=string2
                myHeadSize = myEthlength + myIPHeaderLength + tcph_length * 4
                myPktData = myPacket[myHeadSize:]

                try:
                    decoded_data = myPktData.decode('utf-8')
                    print("Decoded Data : " + decoded_data)
                except UnicodeDecodeError:
                    print("Failed to decode data as UTF-8")

                string3 = ("Raw Data : " + Yellow + str(myPktData) + Reset)
                print(string3)
                output +=string3


            elif protocol == 1:
                u = myEthlength + myIPHeaderLength
                myICMPHeaderLength = 4
                icmp_header = myPacket[u:u + myICMPHeaderLength]
                icmph = struct.unpack("!BBH", icmp_header)
                icmp_type = icmph[0]
                code = icmph[1]
                checksum = icmph[2]

                string4 =(
                        Yellow + "ICMP PACKET!! " + Reset + " Type :" + Cyan + str(icmp_type) + Reset + " Code: " + Cyan + str(code) + Reset + " Checksum : " + Cyan + str(checksum) + Reset)
                print(string4)
                output += string4
                myHeaderSize = myEthlength + myIPHeaderLength + myICMPHeaderLength
                myPktData = myPacket[myHeaderSize:]

                try:
                    decoded_data = myPktData.decode('utf-8')
                    print("Decoded Data : " + decoded_data)
                except UnicodeDecodeError:
                    print("Failed to decode data as UTF-8")

                string5 =("Data : " + Yellow + str(myPktData) + Reset)
                print(string5)
                output +=string5
            elif protocol == 17:
                u = myEthlength + myIPHeaderLength
                myUDPHeaderLength = 8
                myUDPHeader = myPacket[u:u + myUDPHeaderLength]
                udph = struct.unpack("!HHHH", myUDPHeader)
                myScrPort = udph[0]
                myDstPort = udph[1]
                length = udph[2]
                checksum = udph[3]

                string6 = (Yellow + "UDP PACKET!! " + Reset + "Source Port : " + Blue + str(myScrPort) + Reset + " Destination Port : " + Blue + str(myDstPort) + Reset + " Length : " + Blue + str(length) + Reset + " Checksum : " + Blue + str(checksum) + Reset)
                print(string6)
                output +=string6
                myHeaderSize = myEthlength + myIPHeaderLength + myUDPHeaderLength
                myPktData = myPacket[myHeaderSize:]

                try:
                    decoded_data = myPktData.decode('utf-8')
                    print("Decoded Data : " + decoded_data)
                except UnicodeDecodeError:
                    print("Failed to decode data as UTF-8")

                string7 =("Raw Data : " + Yellow + str(myPktData) + Reset)
                print(string7)
                output +=string7


            else:
                string9 =("Protocol Other Than TCP/UDP/ICMP")
                print(string9)
                output +=string9
            continue
        save_output_to_file(output)# Skip to the next iteration of the loop
except KeyboardInterrupt:
    print("\nProgram interrupted. Saving output to file...")
    save_output_to_file("Program interrupted by KeyboardInterrupt")
except Exception as e:
    print("\nAn error occurred. Saving output to file...")
    exception_string = traceback.format_exc()
    save_output_to_file(f"Error occurred: {str(e)}\n{exception_string}")
finally:
    print("Closing the program.")
   
