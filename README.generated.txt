synfrag
    A network scanning tool for sending fragmented IPv4 and IPv6 packets.

Description
    synfrag is a network scanning and penetration testing tool used to craft
    and send fragmented and unfragmented IPv4 and IPv6 packets. It currently
    supports sending both TCP SYN, ICMP echo (ping), and ICMP6 echo packets.
    Various fragmentation configurations are also available. synfrag tries
    its best to read any replies sent by targeted hosts to determine if they
    are willing or able to respond.

    The purpose of synfrag is to test host and network responses to
    fragmented requests. Many current routers implement access control lists
    (ACLs) in a manner that is unable to properly detect traffic inside
    fragmented IP packets, leading to situations where hosts are believed to
    be isolated from internet traffic by these ACLs. In some cases,
    specially crafted packets can bypass these router ACLs by taking
    advantage of their inability to properly process fragmented packets,
    exposing hosts to the internet unprotected.

    Some operating systems implement a security mechanism that ignores
    fragmented TCP SYN packets, preventing connections from being
    established under the assumption that these packets are abnormal and
    specially designed to circumvent network protections. However, many of
    these operating systems do not implement the same protections for all
    protocols, allowing some fragmented traffic through while blocking
    others.

Notes
    synfrag is currently under development and is missing some useful
    features. Namely, synfrag does not resolve hostnames nor discover the
    next-hop layer 2 address, and requires the user to specify these
    parameters.

    Additionally, synfrag does not attempt to prevent the host operating
    system from interpreting any replies received from scanned hosts,
    meaning that after a scan the operating system may send a TCP RST packet
    to the scanned host, misinterpreting its reply as meant for the
    operating system. This can be worked around via firewall rules.

    TCP SYN requests sent by synfrag currently all use the source port
    44128. The same number is used for ICMP/6 echo packet IDs. When writing
    firewall rules to prevent the operating system from misinterpreting
    replies or to prevent synfrag scans, traffic sent to (or from) this
    port, or with this ICMP echo ID, can be discarded.

Examples
  v4-tcp
    The following example uses synfrag to probe TCP port 22 via unfragmented
    IPv4. Note that the dstmac parameter is set to that of the router
    between the srcip's network and the dstip's network:

     %sudo ./synfrag \
      --srcip 10.72.122.120 \
      --dstip 10.72.107.254 \
      --interface eth1 \
      --dstmac 00:00:0C:07:AC:01 \
      --dstport 22 \
      --test v4-tcp
     Starting test "v4-tcp". Opening interface "eth1".
     
 Ethernet Frame, ethertype 2048
      Src MAC 00:1A:4B:C6:F5:2E
      Dest MAC 00:00:0C:07:AC:01
     
 IPv4 Packet:
      Src IP: 10.72.122.120
      Dst IP: 10.72.107.254
      Protocol: 6
      Frag Offset: 0
      Flags: 0
      Iphl: 5
     
 TCP Packet:
      Src Port: 44128
      Dst Port: 22
      Seq Num: 6026158
      Ack Num: 0
      Syn: 1
      Ack: 0
      Rst: 0
     
 Packet transmission successful, waiting for reply...
     
 IPv4 Packet:
      Src IP: 10.72.107.254
      Dst IP: 10.72.122.120
      Protocol: 6
      Frag Offset: 0
      Flags: 2
      Iphl: 5
     
 TCP Packet:
      Src Port: 22
      Dst Port: 44128
      Seq Num: 321403012
      Ack Num: 6026159
      Syn: 1
      Ack: 1
      Rst: 0
     
 Test was successful.

  v4-frag-optioned-tcp
    In this example, synfrag will send a fragmented IPv4 TCP SYN packet to
    the target host, with the initial fragment padded out to 68 bytes. Most
    hosts will drop fragmented IPv4 TCP SYN packets, which is the case
    below:

     sudo ./synfrag \
      --srcip 10.72.122.120 \
      --dstip 10.72.107.254 \
      --interface eth1 \
      --dstmac 00:00:0C:07:AC:01 \
      --dstport 22 \
      --test v4-frag-optioned-tcp
     Starting test "v4-frag-optioned-tcp". Opening interface "eth1".
     
 Ethernet Frame, ethertype 2048
      Src MAC 00:1A:4B:C6:F5:2E
      Dest MAC 00:00:0C:07:AC:01
     
 IPv4 Packet:
      Src IP: 10.72.122.120
      Dst IP: 10.72.107.254
      Protocol: 6
      Frag Offset: 0
      Flags: 1
      Iphl: 13
     
 TCP Packet:
      Src Port: 44128
      Dst Port: 22
      Seq Num: 480622439
      Ack Num: 2153185280
      Syn: 1
      Ack: 0
      Rst: 0
     
 IPv4 Packet:
      Src IP: 10.72.122.120
      Dst IP: 10.72.107.254
      Protocol: 6
      Frag Offset: 1
      Flags: 0
      Iphl: 5
     
 Packet transmission successful, waiting for reply...
     
 Test failed, no response before time out (10 seconds).

License
    synfrag is released under the BSD license. synfrag includes BSD licensed
    code from libnet, and links against libpcap, also licensed under the BSD
    license.

Copyright
    Copyright 2012, Yahoo! Inc. All rights reserved.

Author
    John Eaglesham

Changes
  1.1 - 20120215
    Initial release as open source, thanks Yahoo!

    Converted documentation to POD, added examples.

    Fixed extra free() after timeout.

    Print pretty flag names.

    Allow users to specify a timeout period.

  1.0 - 20120209
    Internal release.

