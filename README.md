Windows Raw Socket Packet Sniffer

This project is a simple packet sniffer for Windows, built using Python’s low-level socket module.
It captures raw IP packets, decodes their headers, and displays key information such as:

Source IP

Destination IP

Protocol (ICMP, TCP, UDP, etc.)

⚠️ Important: Raw sockets require administrator privileges and work differently across operating systems.
This script is specifically designed for Windows systems.

🚀 Features

Captures raw IP packets in real time

Decodes the IP header using struct

Identifies protocols (ICMP, TCP, UDP)

Uses Windows promiscuous mode via SIO_RCVALL

Lightweight and easy to run

📦 Requirements

Python 3.x

Windows OS (raw socket support)

Admin/Administrator privileges to run raw sockets

📥 Installation

Clone the repository and navigate into the project folder:

git clone https://github.com/your-username/your-repo.git
cd your-repo


No third-party libraries are required.

▶️ Usage

Run the script with Python (as Administrator):

python projcet.py


You will see output like:

📦 Packet Captured:
   Source IP      : 192.168.1.10
   Destination IP : 142.250.190.14
   Protocol       : TCP


Stop the sniffer anytime using CTRL + C.

🧠 How It Works

Creates a raw socket using socket.AF_INET + socket.SOCK_RAW.

Binds to the local host machine.

Enables promiscuous mode with SIO_RCVALL.

Continuously listens for packets via recvfrom.

Extracts and decodes the IP header manually using struct.unpack.

⚠️ Legal & Ethical Use

This tool is intended only for learning, testing, and analyzing your own network.
Unauthorized packet sniffing on networks you do not own or control may be illegal.

📄 License

This project is released under the MIT License.
Feel free to modify and use for personal or educational purposes.
