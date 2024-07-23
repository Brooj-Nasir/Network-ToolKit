import tkinter as tk
from functools import partial
import pandas as pd
import matplotlib.pyplot as plt
import binascii
from termcolor import colored
from scapy.layers.l2 import Ether
from scapy.layers.inet import IP, TCP, UDP
from tkinter import scrolledtext
from scapy.all import *
from tkinter import simpledialog, messagebox, filedialog, scrolledtext
from functools import partial
from scapy.all import ICMP, IP, TCP, UDP, sr1, rdpcap
import os
import socket
import threading
from nfuzz.WebFuzzer import WebFormFuzzer
from nfuzz.WebFuzzer import WebRunner
from nfuzz.MutationFuzzer import MutationFuzzer
import requests
import json

import nmap3
nmap = nmap3.Nmap()



#### Web Fuzzing 
web_banner = """
 █     █░▓█████  ▄▄▄▄        █████▒█    ██ ▒███████▒▒███████▒ ██▓ ███▄    █   ▄████ 
▓█░ █ ░█░▓█   ▀ ▓█████▄    ▓██   ▒ ██  ▓██▒▒ ▒ ▒ ▄▀░▒ ▒ ▒ ▄▀░▓██▒ ██ ▀█   █  ██▒ ▀█▒
▒█░ █ ░█ ▒███   ▒██▒ ▄██   ▒████ ░▓██  ▒██░░ ▒ ▄▀▒░ ░ ▒ ▄▀▒░ ▒██▒▓██  ▀█ ██▒▒██░▄▄▄░
░█░ █ ░█ ▒▓█  ▄ ▒██░█▀     ░▓█▒  ░▓▓█  ░██░  ▄▀▒   ░  ▄▀▒   ░░██░▓██▒  ▐▌██▒░▓█  ██▓
░░██▒██▓ ░▒████▒░▓█  ▀█▓   ░▒█░   ▒▒█████▓ ▒███████▒▒███████▒░██░▒██░   ▓██░░▒▓███▀▒
░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒    ▒ ░   ░▒▓▒ ▒ ▒ ░▒▒ ▓░▒░▒░▒▒ ▓░▒░▒░▓  ░ ▒░   ▒ ▒  ░▒   ▒ 
  ▒ ░ ░   ░ ░  ░▒░▒   ░     ░     ░░▒░ ░ ░ ░░▒ ▒ ░ ▒░░▒ ▒ ░ ▒ ▒ ░░ ░░   ░ ▒░  ░   ░ 
  ░   ░     ░    ░    ░     ░ ░    ░░░ ░ ░ ░ ░ ░ ░ ░░ ░ ░ ░ ░ ▒ ░   ░   ░ ░ ░ ░   ░ 
    ░       ░  ░ ░                   ░       ░ ░      ░ ░     ░           ░       ░ 
                      ░                    ░        ░                               
"""
    
working_banner = """
╦ ╦┌─┐┬─┐┌─┐  ┬┌─┐  ┬ ┬┌─┐┬ ┬┬─┐  ┬─┐┌─┐┌─┐┌─┐┬─┐┌┬┐
╠═╣├┤ ├┬┘├┤   │└─┐  └┬┘│ ││ │├┬┘  ├┬┘├┤ ├─┘│ │├┬┘ │ 
╩ ╩└─┘┴└─└─┘  ┴└─┘   ┴ └─┘└─┘┴└─  ┴└─└─┘┴  └─┘┴└─ ┴ 
\n\n
"""
def webformFuzzing(url, count, output_text):
    if not url or not count:
        messagebox.showerror("Error", "Please fill in the URL and Count")
        return

    clear_output(output_text)
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, web_banner, "center")
    output_text.insert(tk.END, working_banner, "center")

    time.sleep(2)
    httpd_url = base_url = url
    web_form_fuzzer = WebFormFuzzer(httpd_url)
    web_form_fuzzer.fuzz()
    web_form_runner = WebRunner(base_url)
    results = []
    for i in range(int(count)):
        out = web_form_fuzzer.runs(web_form_runner, 1)
        results.append(out)

    if results:
        for result in results:
            output_text.insert(tk.END, result)
            output_text.insert(tk.END, "\n")
    else:
        output_text.insert(tk.END, "Sorry, we couldn't find anything")



def mutationFuzzing(url, count, output_text):
    if not url or not count :
        messagebox.showerror("Error", "Please fill in the URL and Count")
        return
    
    clear_output(output_text)
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, web_banner, "center")
    output_text.insert(tk.END, working_banner, "center")

    seed_input = url
    mutation_fuzzer = MutationFuzzer(seed=[seed_input])
    for i in range(0, int(count)):
        inp = mutation_fuzzer.fuzz()
        output_text.insert(tk.END, url+inp)
        output_text.insert(tk.END, "\n")

############

def scan_ports(ip, port, output_text):
    result = ""
    for p in port.split(','):
        packet = IP(dst=ip)/TCP(dport=int(p), flags="S")
        response = sr1(packet, timeout=1, verbose=0)
        if response is not None:
            result += f"Port {p}: Open\n"
        else:
            result += f"Port {p}: Closed\n"

    port_report_banner = """
  , __                                        , __                    
 /|/  \                ()                    /|/  \                   
  |___/ __  ,_ _|_     /\ __  __,   _  _      |___/ _   _  __  ,_ _|_ 
  |    /  \/  | |     /  /   /  |  / |/ |     | \  |/ |/ \/  \/  | |  
  |    \__/   |_|_/  /(__\___\_/|_/  |  |_/   |  \_|__|__/\__/   |_|_/
                                                     /|               
                                                     \|               
"""
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, port_report_banner, "center")
    output_text.insert(tk.END, result)

def send_icmp(ip, message, count, output_text):
    for _ in range(int(count)):
        packet = IP(dst=ip)/ICMP()/(message.encode())
        output_packet_info(packet, output_text)

def send_tcp(ip, port, message, count, output_text):
    for _ in range(int(count)):
        packet = IP(dst=ip)/TCP(dport=int(port))/message
        output_packet_info(packet, output_text)

def send_udp(ip, port, message, count, output_text):
    for _ in range(int(count)):
        packet = IP(dst=ip)/UDP(dport=int(port))/message
        output_packet_info(packet, output_text)

#def send_udp(ip, port, message, count, output_text):
   #  try:
   #     # Create a UDP socket
   #   sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  #    for _ in range(0, int(count)):
#             # Send the UDP packet
#             sock.sendto(message.encode(), (ip, int(port)))
#             # print("UDP packet sent successfully to {}:{}".format(ip, port))
#             output_text.insert(tk.END, ("UDP packet sent successfully to {}:{}".format(ip, int(port))), "center")
#         data, addr = sock.recvfrom(1024)
#         prt = "Received response:", data.decode(), "from", addr
#         output_text.insert(tk.END, prt, "center")
#     except Exception as e:
#         # print("Error sending UDP packets:", e)
#         output_text.insert(tk.END, ("Error sending UDP packets:", e), "center")
#     finally:
#         # Close the socket
#         sock.close()



def send_udp(ip, port, message, count, output_text):
    try:
        # Create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        for _ in range(0, int(count)):
            # Send the UDP packet
            sock.sendto(message.encode(), (ip, int(port)))
            output_text.insert(tk.END, "UDP packet sent successfully to {}:{}".format(ip, int(port)) + "\n", "center")
        data, addr = sock.recvfrom(1024)
        prt = "Received response: {} from {}".format(data.decode(), addr)
        output_text.insert(tk.END, prt + "\n", "center")
    except Exception as e:
        output_text.insert(tk.END, "Error sending UDP packets: {}".format(e) + "\n", "center")
    finally:
        # Close the socket
        sock.close()



def output_packet_info(packet, output_text):
    banner = """
   __                         , __                    
  /\_\/                      /|/  \                   
 |    |    _|_  _      _|_    |___/ _   _  __  ,_ _|_ 
 |    |   | | |/ \|   | |     | \  |/ |/ \/  \/  | |  
  \__/ \_/|_|_|__/ \_/|_|_/   |  \_|__|__/\__/   |_|_/
             /|                      /|               
             \|                      \|               
"""
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, banner, "center")
    try:
        output_text.insert(tk.END, "[+] Total Packets Sent\n")
        output_text.tag_configure('white', foreground='white')
        output_text.insert(tk.END, str(len(packet)) + '\n', 'white')
        output_text.tag_configure('dark green', foreground='dark green')
    except:
        pass
    
    try:
        output_text.insert(tk.END, "\n[+] Packets Summary\n")
        output_text.tag_configure('white', foreground='white')
        output_text.insert(tk.END, packet.summary() + '\n', 'white')
        output_text.tag_configure('dark green', foreground='dark green')
    except:
        pass
    
    try:
        hex_dump = packet.show(dump=True)
        output_text.insert(tk.END, "\n[+] Packets HexDump\n")
        output_text.tag_configure('white', foreground='white')
        output_text.insert(tk.END, hex_dump + '\n', 'white')
        output_text.tag_configure('dark green', foreground='dark green')
    except:
        pass
    
    try:
        filtered_packets = packet.filter(lambda pkt: pkt.haslayer(ICMP))
        output_text.insert(tk.END, "\n[+] Filtered Packets Summary\n")
        output_text.tag_configure('white', foreground='white')
        output_text.insert(tk.END, filtered_packets.summary() + '\n', 'white')
        output_text.tag_configure('dark green', foreground='dark green')
    except:
        pass

def fuzz_icmp(ip, count, output_text):
    with open("myfile.txt", "r") as file:
        payloads = file.readlines()[:int(count)]
        for payload in payloads:
            packet = IP(dst=ip)/ICMP()/(payload.strip().encode())
            output_packet_info(packet, output_text)

def fuzz_tcp(ip, port, count, output_text):
    with open("myfile.txt", "r") as file:
        payloads = file.readlines()[:int(count)]
        for payload in payloads:
            packet = IP(dst=ip)/TCP(dport=int(port))/payload.strip()
            output_packet_info(packet, output_text)

def fuzz_udp(ip, port, count, output_text):
    with open("myfile.txt", "r") as file:
        payloads = file.readlines()[:int(count)]
        for payload in payloads:
            packet = IP(dst=ip)/UDP(dport=int(port))/payload.strip()
            output_packet_info(packet, output_text)

def clear_output(output_text):
    output_text.delete('1.0', tk.END)

def create_styler(parent, text, row, column):
    label = tk.Label(parent, text=text, padx=15, pady=8)
    entry = tk.Entry(parent, width=20)
    label.grid(row=row, column=column, sticky=tk.E)
    entry.grid(row=row, column=column+1)
    return entry

def main():
    root = tk.Tk()
    root.title("Network Toolkit")
    
    # Create output section
    output_frame = tk.Frame(root)
    output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
    
    output_text = scrolledtext.ScrolledText(output_frame, wrap=tk.WORD, bg="dark blue", fg="white")
    output_text.pack(fill=tk.BOTH, expand=True)

    # Display welcome message
    welcome_message = """\n\n\n\n\n

██╗    ██╗███████╗██╗      ██████╗ ██████╗ ███╗   ███╗███████╗
██║    ██║██╔════╝██║     ██╔════╝██╔═══██╗████╗ ████║██╔════╝
██║ █╗ ██║█████╗  ██║     ██║     ██║   ██║██╔████╔██║█████╗  
██║███╗██║██╔══╝  ██║     ██║     ██║   ██║██║╚██╔╝██║██╔══╝  
╚███╔███╔╝███████╗███████╗╚██████╗╚██████╔╝██║ ╚═╝ ██║███████╗
 ╚══╝╚══╝ ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝     ╚═╝╚══════╝
                                                              
"""
    welcome_message_2 = """\n\n\t\t\t
╔╗ ┬ ┬  ╔╗ ┬─┐┌─┐┌─┐ ┬
╠╩╗└┬┘  ╠╩╗├┬┘│ ││ │ │
╚═╝ ┴   ╚═╝┴└─└─┘└─┘└┘

"""
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, welcome_message, "center")
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, welcome_message_2, "center")

    # Create input section
    input_frame = tk.Frame(root)
    input_frame.pack(side=tk.LEFT, fill=tk.Y)
    
    message_entry = create_styler(input_frame, "Message:", 0, 0)
    const_entry = create_styler(input_frame, "Const:", 1, 0)
    ip_entry = create_styler(input_frame, "IP:", 2, 0)
    port_entry = create_styler(input_frame, "Port:", 3, 0)
    url_entry = create_styler(input_frame, "URL:", 4, 0)

    # Create buttons
    # button_frame = tk.Frame(root)
    # button_frame.pack(side=tk.LEFT, fill=tk.Y)

    # Create buttons
    button_frame = tk.Frame(root)
    button_frame.pack(side=tk.RIGHT, fill=tk.Y)
    
    scan_ports_button = create_button(button_frame, "Ports Scan", 0, 0, lambda: on_scan_ports(ip_entry.get(), port_entry.get(), output_text))
    send_icmp_button = create_button(button_frame, "ICMP Packet Send", 1, 0, lambda: on_send_icmp(ip_entry.get(), message_entry.get(), const_entry.get(), output_text))
    send_tcp_button = create_button(button_frame, "TCP Packet Send", 2, 0, lambda: on_send_tcp(ip_entry.get(), port_entry.get(), message_entry.get(), const_entry.get(), output_text))
    send_udp_button = create_button(button_frame, "UDP Packet Send", 3, 0, lambda: on_send_udp(ip_entry.get(), port_entry.get(), message_entry.get(), const_entry.get(), output_text))
    fuzz_icmp_button = create_button(button_frame, "ICMP Fuzz", 4, 0, lambda: on_fuzz_icmp(ip_entry.get(), const_entry.get(), output_text))
    fuzz_tcp_button = create_button(button_frame, "TCP Fuzz", 5, 0, lambda: on_fuzz_tcp(ip_entry.get(), port_entry.get(), const_entry.get(), output_text))
    fuzz_udp_button = create_button(button_frame, "UDP Fuzz", 6, 0, lambda: on_fuzz_udp(ip_entry.get(), port_entry.get(), const_entry.get(), output_text))
######## Web fuzzers
    webformFuzzing_button = create_button(button_frame, "Web Form Fuzzing", 7, 0, lambda: webformFuzzing(url_entry.get(),const_entry.get(), output_text))
    mutationFuzzing_button = create_button(button_frame, "Web Mutate Fuzing", 8, 0, lambda: mutationFuzzing(url_entry.get(),const_entry.get(), output_text))
######## nmap
    topPortScan_button = create_button(button_frame, "Scan Top Ports", 9, 0, lambda: scan_top_ports(ip_entry.get(), output_text))
    DNSBruteScript_button = create_button(button_frame, "Nmap DNS Brute Script", 10, 0, lambda: nmap_dns_brute_script(url_entry.get(), output_text))
    OSdetection_button = create_button(button_frame, "Nmap OS Detection", 11, 0, lambda: nmap_os_detection(ip_entry.get(), output_text))
    VersionsDetection_button = create_button(button_frame, "Nmap Versions Detection", 12, 0, lambda: nmap_version_detection(url_entry.get(), output_text))
    ListScan_button = create_button(button_frame, "Nmap List Scan", 13, 0, lambda: nmap_list_scan(url_entry.get(), output_text))
    subnetScan_button = create_button(button_frame, "Nmap Subnet Scan", 14, 0, lambda: nmap_subnet_scan(url_entry.get(), output_text))
    FinScan_button = create_button(button_frame, "Nmap FIN Scan", 15, 0, lambda: nmap_fin_scan(ip_entry.get(), output_text))
    IdleScan_button = create_button(button_frame, "Nmap IDLE Scan", 16, 0, lambda: nmap_idle_scan(ip_entry.get(), output_text))
    PingScan_button = create_button(button_frame, "Nmap PING Scan", 17, 0, lambda: nmap_ping_scan(ip_entry.get(), output_text))
    SynScan_button = create_button(button_frame, "Nmap SYN Scan", 18, 0, lambda: nmap_syn_scan(ip_entry.get(), output_text))
    TcpScan_button = create_button(button_frame, "Nmap TCP Scan", 19, 0, lambda: nmap_tcp_scan(ip_entry.get(), output_text))
    UdpScan_button = create_button(button_frame, "Nmap UDP Scan", 20, 0, lambda: nmap_udp_scan(ip_entry.get(), output_text))
    PortScanOnly_button = create_button(button_frame, "Nmap Port Scan Only", 21, 0, lambda: nmap_portscan_only(url_entry.get(), output_text))
    noPortScan_button = create_button(button_frame, "Nmap No Port Scan", 22, 0, lambda: nmap_no_portscan(url_entry.get(), output_text))
    ArpDiscovery_button = create_button(button_frame, "Nmap ARP Discovery", 23, 0, lambda: nmap_arp_discovery(url_entry.get(), output_text))
    disableDNS_button = create_button(button_frame, "Nmap Disable DNS", 24, 0, lambda: nmap_disable_dns(url_entry.get(), output_text))
    VulnersScript_button = create_button(button_frame, "Nmap Vulners Script", 25, 0, lambda: nmap_vulners_script(url_entry.get(), output_text))
############
    clear_button = create_button(button_frame, "Clear Output", 26, 0, lambda: clear_output(output_text))
#############
    root.mainloop()

def create_button(parent, text, row, column, command): #for same size buttons and style
    button = tk.Button(parent, text=text, command=command, width=25, bg="black", fg="white")
    button.grid(row=row, column=column, columnspan=1, pady=1.5)  # Adjust columnspan to your preference
    return button


########### nmap


nmap_banner = """
 ███▄    █  ███▄ ▄███▓ ▄▄▄       ██▓███      ██▀███  ▓█████  ██▓███   ▒█████   ██▀███  ▄▄▄█████▓
 ██ ▀█   █ ▓██▒▀█▀ ██▒▒████▄    ▓██░  ██▒   ▓██ ▒ ██▒▓█   ▀ ▓██░  ██▒▒██▒  ██▒▓██ ▒ ██▒▓  ██▒ ▓▒
▓██  ▀█ ██▒▓██    ▓██░▒██  ▀█▄  ▓██░ ██▓▒   ▓██ ░▄█ ▒▒███   ▓██░ ██▓▒▒██░  ██▒▓██ ░▄█ ▒▒ ▓██░ ▒░
▓██▒  ▐▌██▒▒██    ▒██ ░██▄▄▄▄██ ▒██▄█▓▒ ▒   ▒██▀▀█▄  ▒▓█  ▄ ▒██▄█▓▒ ▒▒██   ██░▒██▀▀█▄  ░ ▓██▓ ░ 
▒██░   ▓██░▒██▒   ░██▒ ▓█   ▓██▒▒██▒ ░  ░   ░██▓ ▒██▒░▒████▒▒██▒ ░  ░░ ████▓▒░░██▓ ▒██▒  ▒██▒ ░ 
░ ▒░   ▒ ▒ ░ ▒░   ░  ░ ▒▒   ▓▒█░▒▓▒░ ░  ░   ░ ▒▓ ░▒▓░░░ ▒░ ░▒▓▒░ ░  ░░ ▒░▒░▒░ ░ ▒▓ ░▒▓░  ▒ ░░   
░ ░░   ░ ▒░░  ░      ░  ▒   ▒▒ ░░▒ ░          ░▒ ░ ▒░ ░ ░  ░░▒ ░       ░ ▒ ▒░   ░▒ ░ ▒░    ░    
   ░   ░ ░ ░      ░     ░   ▒   ░░            ░░   ░    ░   ░░       ░ ░ ░ ▒    ░░   ░   ░      
         ░        ░         ░  ░               ░        ░  ░             ░ ░     ░              
                                                                                                

"""

def scan_top_ports(ip, output_text):
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return
    
    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.scan_top_ports(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_dns_brute_script(url, output_text):
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    results = nmap.nmap_dns_brute_script(url)
    clear_output(output_text)
    output_text.insert(tk.END, results)

def nmap_os_detection(ip, output_text):
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_os_detection(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)

def nmap_version_detection(url, output_text):
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_version_detection(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_list_scan(url, output_text):
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_list_scan(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_subnet_scan(url, output_text):
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_subnet_scan(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_fin_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return
    
    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_fin_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_idle_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_idle_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_ping_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_ping_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)

def nmap_syn_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_syn_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)

def nmap_tcp_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_tcp_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_udp_scan(ip, output_text):
    nmap = nmap3.NmapScanTechniques()
    if not ip:
        messagebox.showerror("Error", "Please fill in the IP")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_udp_scan(ip)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_portscan_only(url, output_text):
    nmap = nmap3.NmapHostDiscovery()
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return
    
    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_portscan_only(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_no_portscan(url, output_text):
    nmap = nmap3.NmapHostDiscovery()
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_no_portscan(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_arp_discovery(url, output_text):
    nmap = nmap3.NmapHostDiscovery()
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text) 
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_arp_discovery(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)


def nmap_disable_dns(url, output_text):
    nmap = nmap3.NmapHostDiscovery()
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text)   
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_disable_dns(url)
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)

def nmap_vulners_script(url, output_text): #nmap vulners script to identify vulnerabilities (CVE's)
    nmap = nmap3.Nmap()
    if not url:
        messagebox.showerror("Error", "Please fill in the URL")
        return

    clear_output(output_text)
    output_text.tag_configure("center", justify="center")
    output_text.insert(tk.END, nmap_banner, "center")
    results = nmap.nmap_version_detection(url, args="--script vulners --script-args mincvss+5.0")
    indented_results = json.dumps(results, indent=4)  # Indent the JSON output
    output_text.insert(tk.END, indented_results)
################

def on_scan_ports(ip, port, output_text):
    if not ip or not port:
        messagebox.showerror("Error", "Please fill in the IP and Port fields.")
        return
    clear_output(output_text)
    scan_ports(ip, port, output_text)

def on_send_icmp(ip, message, count, output_text):
    if not ip or not count or not message:
        messagebox.showerror("Error", "Please fill in the IP, Count and Message fields.")
        return
    clear_output(output_text)
    send_icmp(ip, message, count, output_text)

def on_send_tcp(ip, port, message, count, output_text):
    if not ip or not count or not message or not port:
        messagebox.showerror("Error", "Please fill in the IP, Port, Count and Message fields.")
        return
    clear_output(output_text)
    send_tcp(ip, port, message, count, output_text)

def on_send_udp(ip, port, message, count, output_text):
    if not ip or not count or not message or not port:
        messagebox.showerror("Error", "Please fill in the IP, Port, Count and Message fields.")
        return
    clear_output(output_text)
    send_udp(ip, port, message, count, output_text)

def on_fuzz_icmp(ip, count, output_text):
    if not ip or not count:
        messagebox.showerror("Error", "Please fill in the IP and Count fields.")
        return
    clear_output(output_text)
    fuzz_icmp(ip, count, output_text)

def on_fuzz_tcp(ip, port, count, output_text):
    if not ip or not count or not port:
        messagebox.showerror("Error", "Please fill in the IP, Port and Count fields.")
        return
    clear_output(output_text)
    fuzz_tcp(ip, port, count, output_text)

def on_fuzz_udp(ip, port, count, output_text):
    if not ip or not count or not port:
        messagebox.showerror("Error", "Please fill in the IP, Port and Count fields.")
        return
    clear_output(output_text)
    fuzz_udp(ip, port, count, output_text)

if __name__ == "__main__":
    main()
