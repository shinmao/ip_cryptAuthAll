# ip_cryptAuthAll
Source code can be found in `/src`. Please use makefile to compile it. I have tested it on FreeBSD.  

Sender sends the packet which is encrypted by `RC4` and message digest of `MD5`. Receiver would divert the received packet to the other port with `divertlib` program. The most difficult part in the program is to parse the structure of packet. The rest part is the core to make authentication between sender side and receiver side.