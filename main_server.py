#Authert: Dvir Zilber
"""
a program that recives an ip from the same router as the server its running in
and checks which ports from a given range are open.
"""
#Date 01/03/2026

from scapy.all import *

# 1. Get the target IP from the user
target_ip = input("Enter the IP address to scan: ")

# 2. Define the range of ports (20 to 1024 as requested)
start_port = 20
end_port = 1024
port = 20
print(f"Scanning {target_ip} from port {start_port} to {end_port}...")

# 3. Loop through each port
while (port>= 20 and port<= 1024):

    # Create a TCP SYN packet
    # flags="S" means we are sending a SYN packet
    syn_packet = IP(dst=target_ip) / TCP(sport=12345, dport=port, flags="S")

    # Send the packet and wait for a response
    # timeout=0.5 is the recommended time to keep it fast
    response = sr1(syn_packet, timeout=0.5, verbose=False) #the verbose flag makes sure that i only gat the syn+ack (without usless text)
    #print (f"checking for port {port}" ) //this is optional

    # 4. Check the response
    if response:
        # Check if the SYN and ACK flags are both set
        if response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12: #(18 becuse that is the sum of the syn+ack flags)
            print(f"Port {port} is OPEN!")

            #Send a Reset packet to close the connection
            rst_packet = IP(dst=target_ip) / TCP(sport=12345, dport=port, flags="R")
            send(rst_packet, verbose=False)
    port+=1 #adding one value to the port in order to go through 20 to 1024

print("Scan complete.")