Data Formats


NOTE: 
* Data has been anaonymised/edited. 
* You should not attibute any activity in these logs to  any IP address in the  'real world'
* This data is not to be shared with any party or uploaded to any system



Sample data files can be found in ths directory, 

access - Apache access log snippet
error - Apache error log snippet
  
syslog - Linux syslog
auth - Linux auth log

cndnov23example.cap  - PCAP file of the type you have worked with

These may be validated using the hashes below, also contained in checksum.sha256
6fe54c1922968920c26b84c246e0e120cbce888088102c1eabb4a22cde037be6  access
a8607cce380f3123e3748149eb0e9ae72bd95313e3a0af26e6a4263ba12b26ab  auth
c43dc48b3b12ad9ca851afac08e9ae8d0ff06786ade993a42e5de954fe43af23  cndnov23example.cap
eb3c5a094ff865e03c07d40f6f0d15d6b9e66245dd8cf6073d2b40d664934554  error
81ee03666cdd8f47e941201417bdddcd6ab4e6064ea3616ec0e11ac632fe338f  syslog



Example Pcap Data
=======================================
Data was captured on a system using UTC Time (GMT). The following was produced on a system set to Europe/Oslo
root@cnd2023:/home/cnd# timedatectl
               Local time: Tue 2023-11-21 23:19:52 CET
           Universal time: Tue 2023-11-21 22:19:52 UTC
                 RTC time: Tue 2023-11-21 22:19:52
                Time zone: Europe/Oslo (CET, +0100)
System clock synchronized: yes
              NTP service: active
          RTC in local TZ: no



File name:           cndnov23example.cap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   2,283 k
File size:           197 MB
Data size:           161 MB
Capture duration:    86399.958621 seconds
First packet time:   2023-10-05 01:00:00.015787
Last packet time:    2023-10-06 00:59:59.974408
Data byte rate:      1,864 bytes/s
Data bit rate:       14 kbps
Average packet size: 70.53 bytes
Average packet rate: 26 packets/s
SHA256:              c43dc48b3b12ad9ca851afac08e9ae8d0ff06786ade993a42e5de954fe43af23
RIPEMD160:           7c86d0447c5ca284c7fec98586c3b1d8d4883415
SHA1:                b676d42f8a534c921a35ae950b8bb35b4befdc9c
Strict time order:   False
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535
                     Time precision = microseconds (6)
                     Time ticks per second = 1000000
                     Number of stat entries = 0
                     Number of packets = 2283597
root@cnd2023:/home/cnd# File name:           foo2.cap
File type:           Wireshark/tcpdump/... - pcap
File encapsulation:  Ethernet
File timestamp precision:  microseconds (6)
Packet size limit:   file hdr: 65535 bytes
Number of packets:   2,283 k
File size:           197 MB
Data size:           161 MB
Capture duration:    86399.958621 seconds
First packet time:   2023-10-05 01:00:00.015787
Last packet time:    2023-10-06 00:59:59.974408
Data byte rate:      1,864 bytes/s
Data bit rate:       14 kbps
Average packet size: 70.53 bytes
Average packet rate: 26 packets/s
SHA256:              c43dc48b3b12ad9ca851afac08e9ae8d0ff06786ade993a42e5de954fe43af23
RIPEMD160:           7c86d0447c5ca284c7fec98586c3b1d8d4883415
SHA1:                b676d42f8a534c921a35ae950b8bb35b4befdc9c
Strict time order:   False
Number of interfaces in file: 1
Interface #0 info:
                     Encapsulation = Ethernet (1 - ether)
                     Capture length = 65535

