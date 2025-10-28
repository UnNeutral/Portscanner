🚀 **Advanced Port Scanner in Python**

This project is a multi-threaded Port Scanner built in Python, designed to quickly and accurately identify open TCP and UDP ports on a target host. It supports configurable port ranges, optional CSV output, and both TCP and UDP scanning modes.


**📊 Key Features**

Multi-threaded Scanning: Uses Python’s threading module for faster concurrent scans.

TCP & UDP Support: Detects open and closed ports for both TCP and UDP protocols.

Custom Port Range: Users can specify single ports, ranges (e.g., 1-1024), or multiple comma-separated ports.

CSV Export: Automatically saves scan results (IP, Port, Status, Protocol) into a CSV file.

Optional Prompts: Includes --yes flag for non-interactive scanning (automatically proceeds without confirmation).

Detailed Logging: Prints real-time scan progress and results on the console.


**⚙️ Under the Hood**

Built using Python’s socket, threading, and csv libraries.

Implements timeouts for reliable detection of active/open ports.

Handles errors and exceptions gracefully to avoid interruptions during large scans.

Includes lightweight synchronization for writing results to file safely across threads.


**🔧 Requirements**

Python 3.x

Works on Linux, Windows, and macOS

Internet connection or local network access to the target host


**🧩 Use Cases**

Network administrators testing for open ports

Security researchers validating firewall configurations

Students learning about networking and socket programming


**🔗 Explore the Project**

Check out the code and contribute on GitHub.
Suggestions, pull requests, and feedback are welcome!

#CyberSecurity #Networking #Python #EthicalHacking #PortScanner
