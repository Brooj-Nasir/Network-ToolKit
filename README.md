# Network Toolkit

## Overview

The Network Toolkit is a GUI based comprehensive network analysis tool built with Python and Tkinter. It combines several functionalities for **network testing**, **fuzzing**, **scanning**, and **packet crafting**, using libraries such as **Scapy**, **Nmap**, and **nfuzz**. This tool provides an intuitive graphical interface for performing various network tasks, including **port scanning**, **packet sending**, and **web fuzzing**.
## GUI:
Here's how the Tool-kit Gui looks like:

![toolkit](https://github.com/user-attachments/assets/de684f04-3c39-4f3d-920c-d2c6f2f9aa1c)


## Features

- **Port Scanning**: Check the status of specified ports on a target IP address.
- **Packet Sending**: Send ICMP, TCP, and UDP packets with customizable messages.
- **Fuzzing**: Perform ICMP, TCP, and UDP fuzzing with payloads read from a file.
- **Web Fuzzing**: Use web form and mutation fuzzing techniques to test web applications.
- **Nmap Scanning**: Utilize Nmap to perform various network scans including top ports, DNS brute force, OS detection, and more.
- **GUI Interface**: User-friendly interface built with Tkinter for easy interaction with network testing features.

## How to Use

1. **Run the Application**: Launch the Network Toolkit application.
2. **Input Fields**:
   - **Message**: Enter the message to be sent in packets.
   - **Const**: Specify the count ( How many packets you want to send).
   - **IP**: Enter the target IP address.
   - **Port**: Specify the target port(s).
   - **URL**: Provide the URL for web fuzzing.

3. **Actions**:
   - **Scan Ports**: Click to perform a port scan on the specified IP.
   - **Send Packets**: Choose to send ICMP, TCP, or UDP packets with the specified message.
   - **Fuzzing**: Perform fuzzing tests on ICMP, TCP, or UDP with payloads from a file.
   - **Web Fuzzing**: Use the web fuzzing options to test web forms or perform mutation fuzzing.
   - **Nmap Scans**: Perform various Nmap scans and tests.

4. **View Results**: Results and status messages are displayed in the output section of the GUI.

## Code File

 For code of the Network Toolkit click here [code.py](code.py)

## Requirements

- Python 3.x
- Tkinter
- Scapy
- nfuzz
- nmap3
- Requests
- Pandas
- Matplotlib
- Termcolor

## Installation

1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Brooj-Nasir/Network-ToolKit.git

2. **Navigate to the Project Directory**:

```bash
cd Network-ToolKit
```
3. **Install Dependencies**:

```bash
pip install -r requirements.txt
```
4. **Run the Application**:

```bash
python main.py
```
## Contributions:
Contributions are not Welcome without the permission of the author [/Brooj-Nasir]

## License:
This project is licensed under the Proprietary License. See the [LICENSE](LICENSE) file for details.

## Sample Code:

```python
import tkinter as tk
from functools import partial
from scapy.all import *

def send_icmp(ip, message, count, output_text):
    for _ in range(int(count)):
        packet = IP(dst=ip)/ICMP()/(message.encode())
        output_packet_info(packet, output_text)

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
...
```
