# NetWorkTapper

NetWorkTapper is a packet capture and analysis tool built in C++ using WinPcap/Npcap.

## Features

- List all network interfaces on the system
- Capture and display network traffic in real-time
- Parse and display Ethernet, IPv4, TCP, and UDP packet details

## Requirements

- Visual Studio (the project is configured for Visual Studio 2022)
- WinPcap or Npcap installed on your system

## Installation and Setup

1. Install WinPcap or Npcap on your system
   - [Npcap Download](https://npcap.com/) (recommended)
   - [WinPcap Download](https://www.winpcap.org/install/)

2. Clone this repository
   ```
   git clone https://github.com/yourusername/NetWorkTapper.git
   ```

3. Open the solution file `NetWorkTapper.sln` in Visual Studio

4. The project is already configured to use WinPcap/Npcap libraries from the default installation location:
   - Include directories: `C:\Program Files\Npcap\Include`
   - Library directories: `C:\Program Files\Npcap\Lib\x64`
   - Additional dependencies: `wpcap.lib` and `Packet.lib`

5. Build the solution (F7 or Ctrl+Shift+B)

## How to Use

1. Run the program as administrator (required for packet capture)
2. Select a network interface from the list by entering its number
3. The program will start capturing packets and showing details
4. Press Ctrl+C to stop the capture

## Project Structure

- `main.cpp`: Contains the core program logic for interface selection and packet capture
- `networkheader.h`: Defines the structures for various network protocol headers
- `networkheader.cpp`: Implements helper functions for packet analysis

## License

This project is licensed under the MIT License.

## Notes

- Running in administrator mode is required for network packet capture
- The code uses C-style casts when dealing with network structures as is common in packet capture code 