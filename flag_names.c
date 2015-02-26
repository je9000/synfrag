/*
 * Copyright (c) 2012, Yahoo! Inc All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     Redistributions of source code must retain the above copyright notice,
 *     this list of conditions and the following disclaimer.  Redistributions
 *     in binary form must reproduce the above copyright notice, this list
 *     of conditions and the following disclaimer in the documentation and/or
 *     other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
 * OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: John Eaglesham
 */

#include <stdlib.h>
#include <string.h>

/*
 * The following functions require the user to call free() on the returned
 * pointer.
*/

/* Room for all of the flags as strings plus * one for the NULL. */
#define TCP_FLAG_STRING_MAX_LENGTH ( ( 8 * 5 ) + 1 )
char *tcp_flags_to_names( unsigned char flags )
{
    char *str;
    str = (char *) malloc( TCP_FLAG_STRING_MAX_LENGTH );
    if ( str == NULL ) return NULL;

    if ( flags == 0 ) {
        strcpy( str, "None" );
        return str;
    }
    str[0] = '\0';
    if ( flags & ( 1 << 0 ) ) strcat( str, "FIN, " );
    if ( flags & ( 1 << 1 ) ) strcat( str, "SYN, " );
    if ( flags & ( 1 << 2 ) ) strcat( str, "RST, " );
    if ( flags & ( 1 << 3 ) ) strcat( str, "PSH, " );
    if ( flags & ( 1 << 4 ) ) strcat( str, "ACK, " );
    if ( flags & ( 1 << 5 ) ) strcat( str, "URG, " );
    if ( flags & ( 1 << 6 ) ) strcat( str, "ECN, " );
    if ( flags & ( 1 << 7 ) ) strcat( str, "CWR, " );
    str[ strlen(str) - 2 ] = '\0';

    return str;
}

/* Room for all of the flags as strings plus * one for the NULL. */
#define IP_FLAG_STRING_MAX_LENGTH ( ( 3 * 4 ) + 1 )
char *ip_flags_to_names( unsigned char flags )
{
    char *str;
    str = (char *) malloc( IP_FLAG_STRING_MAX_LENGTH );
    if ( str == NULL ) return NULL;

    if ( flags == 0 ) {
        strcpy( str, "None" );
        return str;
    }
    str[0] = '\0';
    if ( flags & ( 1 << 0 ) ) strcat( str, "MF, " );
    if ( flags & ( 1 << 1 ) ) strcat( str, "DF, " );
    if ( flags & ( 1 << 2 ) ) strcat( str, "RE, " );
    str[ strlen(str) - 2 ] = '\0';

    return str;
}

/*
 * The following functions return static strings, the user should not call
 * free() on the returned pointer.
 */
const char *icmp6_type_to_name( unsigned char type )
{
    if ( type == 1 ) return "Destination unreachable";
    if ( type == 2 ) return "Packet too big";
    if ( type == 3 ) return "Time exceeded";
    if ( type == 4 ) return "Invalid IPv6 header";
    if ( type == 128 ) return "Echo service request";
    if ( type == 129 ) return "Echo service reply";
    if ( type == 130 ) return "Group membership query";
    if ( type == 130 ) return "Multicast listener query";
    if ( type == 131 ) return "Group membership report";
    if ( type == 131 ) return "Multicast listener report";
    if ( type == 132 ) return "Group membership termination";
    if ( type == 132 ) return "Multicast listerner done";
    if ( type == 133 ) return "Router solicitation";
    if ( type == 134 ) return "Router advertisement";
    if ( type == 135 ) return "Neighbor solicitation";
    if ( type == 136 ) return "Neighbor advertisement";
    if ( type == 137 ) return "Shorter route exists";
    if ( type == 138 ) return "Route renumbering";
    if ( type == 139 ) return "FQDN query";
    if ( type == 139 ) return "Node information query";
    if ( type == 139 ) return "Who-are-you request";
    if ( type == 140 ) return "FQDN reply";
    if ( type == 140 ) return "Node information reply";
    if ( type == 140 ) return "Who-are-you reply";
    if ( type == 200 ) return "mtrace response";
    if ( type == 201 ) return "mtrace messages";
    return "Unassigned";
}


const char *icmp6_code_to_name( unsigned char type, unsigned char code )
{
    if ( type == 1 ) {
        if ( code == 0 ) return "No route to destination";
        if ( code == 1 ) return "Administratively prohibited";
        if ( code == 2 ) return "Beyond scope of source address";
        if ( code == 2 ) return "Not a neighbor (obselete)";
        if ( code == 3 ) return "Address unreachable";
        if ( code == 4 ) return "Port unreachable";
    }

    if ( type == 3 ) {
        if ( code == 0 ) return "Time exceeded in transit";
        if ( code == 1 ) return "Time exceeded in reassembly";
    }

    if ( type == 4 ) {
        if ( code == 0 ) return "Erroneous header field";
        if ( code == 1 ) return "Unrecognized next header";
    }

    if ( type == 137 ) {
        if ( code == 0 ) return "Redirection to on-link node";
        if ( code == 1 ) return "Redirection to better router";
        if ( code == 2 ) return "Unrecognized option";
    }

    return "Unassigned";
}

const char *icmp_type_to_name( unsigned char type )
{
    if ( type == 0 ) return "Echo Reply";
    if ( type == 3 ) return "Destination Unreachable";
    if ( type == 4 ) return "Source Quench";
    if ( type == 5 ) return "Redirect";
    if ( type == 6 ) return "Alternate Host Address";
    if ( type == 8 ) return "Echo";
    if ( type == 9 ) return "Router Advertisement";
    if ( type == 10 ) return "Router Solicitation";
    if ( type == 11 ) return "Time Exceeded";
    if ( type == 12 ) return "Parameter Problem";
    if ( type == 13 ) return "Timestamp";
    if ( type == 14 ) return "Timestamp Reply";
    if ( type == 15 ) return "Information Request";
    if ( type == 16 ) return "Information Reply";
    if ( type == 17 ) return "Address Mask Request";
    if ( type == 18 ) return "Address Mask Reply";
    if ( type == 19 ) return "Reserved (for Security)";
    if ( type == 30 ) return "Traceroute";
    if ( type == 31 ) return "Datagram Conversion Error";
    if ( type == 32 ) return "Mobile Host Redirect";
    if ( type == 33 ) return "IPv6 Where-Are-You";
    if ( type == 34 ) return "IPv6 I-Am-Here";
    if ( type == 35 ) return "Mobile Registration Request";
    if ( type == 36 ) return "Mobile Registration Reply";
    if ( type == 37 ) return "Domain Name Request";
    if ( type == 38 ) return "Domain Name Reply";
    if ( type == 39 ) return "SKIP";
    if ( type == 40 ) return "Photuris";
    if ( type == 41 ) return "ICMP messages utilized by experimental mobility protocols such as Seamoby";
    return "Unassigned";
}

const char *icmp_code_to_name( unsigned char type, unsigned char code )
{
    if ( type == 3 ) {
        if ( code == 0 ) return "Net Unreachable";
        if ( code == 1 ) return "Host Unreachable";
        if ( code == 2 ) return "Protocol Unreachable";
        if ( code == 3 ) return "Port Unreachable";
        if ( code == 4 ) return "Fragmentation Needed and Don't Fragment was Set";
        if ( code == 5 ) return "Source Route Failed";
        if ( code == 6 ) return "Destination Network Unknown";
        if ( code == 7 ) return "Destination Host Unknown";
        if ( code == 8 ) return "Source Host Isolated";
        if ( code == 9 ) return "Communication with Destination Network is Administratively Prohibited";
        if ( code == 10 ) return "Communication with Destination Host is Administratively Prohibited";
        if ( code == 11 ) return "Destination Network Unreachable for Type of Service";
        if ( code == 12 ) return "Destination Host Unreachable for Type of Service";
        if ( code == 13 ) return "Communication Administratively Prohibited";
        if ( code == 14 ) return "Host Precedence Violation";
        if ( code == 15 ) return "Precedence cutoff in effect";
    }
    if ( type == 5 ) {
        if ( code == 0 ) return "Redirect Datagram for the Network (or subnet)";
        if ( code == 1 ) return "Redirect Datagram for the Host";
        if ( code == 2 ) return "Redirect Datagram for the Type of Service and Network";
        if ( code == 3 ) return "Redirect Datagram for the Type of Service and Host";
    }
    if ( type == 6 ) {
        if ( code == 0 ) return "Alternate Address for Host";
    }
    if ( type == 9 ) {
        if ( code == 0 ) return "Normal router advertisement";
        if ( code == 16 ) return "Does not route common traffic";
    }
    if ( type == 11 ) {
        if ( code == 0 ) return "Time to Live exceeded in Transit";
        if ( code == 1 ) return "Fragment Reassembly Time Exceeded";
    }
    if ( type == 12 ) {
        if ( code == 0 ) return "Pointer indicates the error";
        if ( code == 1 ) return "Missing a Required Option";
        if ( code == 2 ) return "Bad Length";
    }
    if ( type == 40 ) {
        if ( code == 0 ) return "Bad SPI";
        if ( code == 1 ) return "Authentication Failed";
        if ( code == 2 ) return "Decompression Failed";
        if ( code == 3 ) return "Decryption Failed";
        if ( code == 4 ) return "Need Authentication";
        if ( code == 5 ) return "Need Authorization";
    }
    return "Unassigned";
}

const char *ip_protocol_to_name( unsigned char protocol )
{
    if ( protocol == 0 ) return "IPPROTO_IP";
    if ( protocol == 1 ) return "IPPROTO_ICMP";
    if ( protocol == 6 ) return "IPPROTO_TCP";
    if ( protocol == 17 ) return "IPPROTO_UDP";
    if ( protocol == 255 ) return "IPPROTO_RAW";
    if ( protocol == 0 ) return "IPPROTO_HOPOPTS";
    if ( protocol == 2 ) return "IPPROTO_IGMP";
    if ( protocol == 3 ) return "IPPROTO_GGP";
    if ( protocol == 4 ) return "IPPROTO_IPV4";
    if ( protocol == 7 ) return "IPPROTO_ST";
    if ( protocol == 8 ) return "IPPROTO_EGP";
    if ( protocol == 9 ) return "IPPROTO_PIGP";
    if ( protocol == 10 ) return "IPPROTO_RCCMON";
    if ( protocol == 11 ) return "IPPROTO_NVPII";
    if ( protocol == 12 ) return "IPPROTO_PUP";
    if ( protocol == 13 ) return "IPPROTO_ARGUS";
    if ( protocol == 14 ) return "IPPROTO_EMCON";
    if ( protocol == 15 ) return "IPPROTO_XNET";
    if ( protocol == 16 ) return "IPPROTO_CHAOS";
    if ( protocol == 18 ) return "IPPROTO_MUX";
    if ( protocol == 19 ) return "IPPROTO_MEAS";
    if ( protocol == 20 ) return "IPPROTO_HMP";
    if ( protocol == 21 ) return "IPPROTO_PRM";
    if ( protocol == 22 ) return "IPPROTO_IDP";
    if ( protocol == 23 ) return "IPPROTO_TRUNK1";
    if ( protocol == 24 ) return "IPPROTO_TRUNK2";
    if ( protocol == 25 ) return "IPPROTO_LEAF1";
    if ( protocol == 26 ) return "IPPROTO_LEAF2";
    if ( protocol == 27 ) return "IPPROTO_RDP";
    if ( protocol == 28 ) return "IPPROTO_IRTP";
    if ( protocol == 29 ) return "IPPROTO_TP";
    if ( protocol == 30 ) return "IPPROTO_BLT";
    if ( protocol == 31 ) return "IPPROTO_NSP";
    if ( protocol == 32 ) return "IPPROTO_INP";
    if ( protocol == 33 ) return "IPPROTO_SEP";
    if ( protocol == 34 ) return "IPPROTO_3PC";
    if ( protocol == 35 ) return "IPPROTO_IDPR";
    if ( protocol == 36 ) return "IPPROTO_XTP";
    if ( protocol == 37 ) return "IPPROTO_DDP";
    if ( protocol == 38 ) return "IPPROTO_CMTP";
    if ( protocol == 39 ) return "IPPROTO_TPXX";
    if ( protocol == 40 ) return "IPPROTO_IL";
    if ( protocol == 41 ) return "IPPROTO_IPV6";
    if ( protocol == 42 ) return "IPPROTO_SDRP";
    if ( protocol == 43 ) return "IPPROTO_ROUTING";
    if ( protocol == 44 ) return "IPPROTO_FRAGMENT";
    if ( protocol == 45 ) return "IPPROTO_IDRP";
    if ( protocol == 46 ) return "IPPROTO_RSVP";
    if ( protocol == 47 ) return "IPPROTO_GRE";
    if ( protocol == 48 ) return "IPPROTO_MHRP";
    if ( protocol == 49 ) return "IPPROTO_BHA";
    if ( protocol == 50 ) return "IPPROTO_ESP";
    if ( protocol == 51 ) return "IPPROTO_AH";
    if ( protocol == 52 ) return "IPPROTO_INLSP";
    if ( protocol == 53 ) return "IPPROTO_SWIPE";
    if ( protocol == 54 ) return "IPPROTO_NHRP";
    if ( protocol == 55 ) return "IPPROTO_MOBILE";
    if ( protocol == 56 ) return "IPPROTO_TLSP";
    if ( protocol == 57 ) return "IPPROTO_SKIP";
    if ( protocol == 58 ) return "IPPROTO_ICMPV6";
    if ( protocol == 59 ) return "IPPROTO_NONE";
    if ( protocol == 60 ) return "IPPROTO_DSTOPTS";
    if ( protocol == 61 ) return "IPPROTO_AHIP";
    if ( protocol == 62 ) return "IPPROTO_CFTP";
    if ( protocol == 63 ) return "IPPROTO_HELLO";
    if ( protocol == 64 ) return "IPPROTO_SATEXPAK";
    if ( protocol == 65 ) return "IPPROTO_KRYPTOLAN";
    if ( protocol == 66 ) return "IPPROTO_RVD";
    if ( protocol == 67 ) return "IPPROTO_IPPC";
    if ( protocol == 68 ) return "IPPROTO_ADFS";
    if ( protocol == 69 ) return "IPPROTO_SATMON";
    if ( protocol == 70 ) return "IPPROTO_VISA";
    if ( protocol == 71 ) return "IPPROTO_IPCV";
    if ( protocol == 72 ) return "IPPROTO_CPNX";
    if ( protocol == 73 ) return "IPPROTO_CPHB";
    if ( protocol == 74 ) return "IPPROTO_WSN";
    if ( protocol == 75 ) return "IPPROTO_PVP";
    if ( protocol == 76 ) return "IPPROTO_BRSATMON";
    if ( protocol == 77 ) return "IPPROTO_ND";
    if ( protocol == 78 ) return "IPPROTO_WBMON";
    if ( protocol == 79 ) return "IPPROTO_WBEXPAK";
    if ( protocol == 80 ) return "IPPROTO_EON";
    if ( protocol == 81 ) return "IPPROTO_VMTP";
    if ( protocol == 82 ) return "IPPROTO_SVMTP";
    if ( protocol == 83 ) return "IPPROTO_VINES";
    if ( protocol == 84 ) return "IPPROTO_TTP";
    if ( protocol == 85 ) return "IPPROTO_IGP";
    if ( protocol == 86 ) return "IPPROTO_DGP";
    if ( protocol == 87 ) return "IPPROTO_TCF";
    if ( protocol == 88 ) return "IPPROTO_IGRP";
    if ( protocol == 89 ) return "IPPROTO_OSPFIGP";
    if ( protocol == 90 ) return "IPPROTO_SRPC";
    if ( protocol == 91 ) return "IPPROTO_LARP";
    if ( protocol == 92 ) return "IPPROTO_MTP";
    if ( protocol == 93 ) return "IPPROTO_AX25";
    if ( protocol == 94 ) return "IPPROTO_IPEIP";
    if ( protocol == 95 ) return "IPPROTO_MICP";
    if ( protocol == 96 ) return "IPPROTO_SCCSP";
    if ( protocol == 97 ) return "IPPROTO_ETHERIP";
    if ( protocol == 98 ) return "IPPROTO_ENCAP";
    if ( protocol == 99 ) return "IPPROTO_APES";
    if ( protocol == 100 ) return "IPPROTO_GMTP";
    if ( protocol == 108 ) return "IPPROTO_IPCOMP";
    if ( protocol == 132 ) return "IPPROTO_SCTP";
    if ( protocol == 103 ) return "IPPROTO_PIM";
    if ( protocol == 112 ) return "IPPROTO_CARP";
    if ( protocol == 113 ) return "IPPROTO_PGM";
    if ( protocol == 240 ) return "IPPROTO_PFSYNC";
    if ( protocol == 254 ) return "IPPROTO_OLD_DIVERT";
    return "Unassigned";
}

const char *ether_protocol_to_name( unsigned short protocol )
{
    if ( protocol == 0x0004 ) return "ETHERTYPE_8023";
    if ( protocol == 0x0200 ) return "ETHERTYPE_PUP";
    if ( protocol == 0x0200 ) return "ETHERTYPE_PUPAT";
    if ( protocol == 0x0500 ) return "ETHERTYPE_SPRITE";
    if ( protocol == 0x0600 ) return "ETHERTYPE_NS";
    if ( protocol == 0x0601 ) return "ETHERTYPE_NSAT";
    if ( protocol == 0x0660 ) return "ETHERTYPE_DLOG1";
    if ( protocol == 0x0661 ) return "ETHERTYPE_DLOG2";
    if ( protocol == 0x0800 ) return "ETHERTYPE_IP";
    if ( protocol == 0x0801 ) return "ETHERTYPE_X75";
    if ( protocol == 0x0802 ) return "ETHERTYPE_NBS";
    if ( protocol == 0x0803 ) return "ETHERTYPE_ECMA";
    if ( protocol == 0x0804 ) return "ETHERTYPE_CHAOS";
    if ( protocol == 0x0805 ) return "ETHERTYPE_X25";
    if ( protocol == 0x0806 ) return "ETHERTYPE_ARP";
    if ( protocol == 0x0807 ) return "ETHERTYPE_NSCOMPAT";
    if ( protocol == 0x0808 ) return "ETHERTYPE_FRARP";
    if ( protocol == 0x0900 ) return "ETHERTYPE_UBDEBUG";
    if ( protocol == 0x0A00 ) return "ETHERTYPE_IEEEPUP";
    if ( protocol == 0x0A01 ) return "ETHERTYPE_IEEEPUPAT";
    if ( protocol == 0x0BAD ) return "ETHERTYPE_VINES";
    if ( protocol == 0x0BAE ) return "ETHERTYPE_VINESLOOP";
    if ( protocol == 0x0BAF ) return "ETHERTYPE_VINESECHO";
    if ( protocol == 0x1000 ) return "ETHERTYPE_TRAIL";
    if ( protocol == 0x1234 ) return "ETHERTYPE_DCA";
    if ( protocol == 0x1600 ) return "ETHERTYPE_VALID";
    if ( protocol == 0x1989 ) return "ETHERTYPE_DOGFIGHT";
    if ( protocol == 0x1995 ) return "ETHERTYPE_RCL";
    if ( protocol == 0x3C00 ) return "ETHERTYPE_NBPVCD";
    if ( protocol == 0x3C01 ) return "ETHERTYPE_NBPSCD";
    if ( protocol == 0x3C02 ) return "ETHERTYPE_NBPCREQ";
    if ( protocol == 0x3C03 ) return "ETHERTYPE_NBPCRSP";
    if ( protocol == 0x3C04 ) return "ETHERTYPE_NBPCC";
    if ( protocol == 0x3C05 ) return "ETHERTYPE_NBPCLREQ";
    if ( protocol == 0x3C06 ) return "ETHERTYPE_NBPCLRSP";
    if ( protocol == 0x3C07 ) return "ETHERTYPE_NBPDG";
    if ( protocol == 0x3C08 ) return "ETHERTYPE_NBPDGB";
    if ( protocol == 0x3C09 ) return "ETHERTYPE_NBPCLAIM";
    if ( protocol == 0x3C0A ) return "ETHERTYPE_NBPDLTE";
    if ( protocol == 0x3C0B ) return "ETHERTYPE_NBPRAS";
    if ( protocol == 0x3C0C ) return "ETHERTYPE_NBPRAR";
    if ( protocol == 0x3C0D ) return "ETHERTYPE_NBPRST";
    if ( protocol == 0x4242 ) return "ETHERTYPE_PCS";
    if ( protocol == 0x424C ) return "ETHERTYPE_IMLBLDIAG";
    if ( protocol == 0x4321 ) return "ETHERTYPE_DIDDLE";
    if ( protocol == 0x4C42 ) return "ETHERTYPE_IMLBL";
    if ( protocol == 0x5208 ) return "ETHERTYPE_SIMNET";
    if ( protocol == 0x6000 ) return "ETHERTYPE_DECEXPER";
    if ( protocol == 0x6001 ) return "ETHERTYPE_MOPDL";
    if ( protocol == 0x6002 ) return "ETHERTYPE_MOPRC";
    if ( protocol == 0x6003 ) return "ETHERTYPE_DECnet";
    if ( protocol == 0x6004 ) return "ETHERTYPE_LAT";
    if ( protocol == 0x6005 ) return "ETHERTYPE_DECDIAG";
    if ( protocol == 0x6006 ) return "ETHERTYPE_DECCUST";
    if ( protocol == 0x6007 ) return "ETHERTYPE_SCA";
    if ( protocol == 0x6008 ) return "ETHERTYPE_AMBER";
    if ( protocol == 0x6009 ) return "ETHERTYPE_DECMUMPS";
    if ( protocol == 0x6558 ) return "ETHERTYPE_TRANSETHER";
    if ( protocol == 0x6559 ) return "ETHERTYPE_RAWFR";
    if ( protocol == 0x7000 ) return "ETHERTYPE_UBDL";
    if ( protocol == 0x7001 ) return "ETHERTYPE_UBNIU";
    if ( protocol == 0x7002 ) return "ETHERTYPE_UBDIAGLOOP";
    if ( protocol == 0x7003 ) return "ETHERTYPE_UBNMC";
    if ( protocol == 0x7005 ) return "ETHERTYPE_UBBST";
    if ( protocol == 0x7007 ) return "ETHERTYPE_OS9";
    if ( protocol == 0x7009 ) return "ETHERTYPE_OS9NET";
    if ( protocol == 0x7030 ) return "ETHERTYPE_RACAL";
    if ( protocol == 0x7031 ) return "ETHERTYPE_PRIMENTS";
    if ( protocol == 0x7034 ) return "ETHERTYPE_CABLETRON";
    if ( protocol == 0x8003 ) return "ETHERTYPE_CRONUSVLN";
    if ( protocol == 0x8004 ) return "ETHERTYPE_CRONUS";
    if ( protocol == 0x8005 ) return "ETHERTYPE_HP";
    if ( protocol == 0x8006 ) return "ETHERTYPE_NESTAR";
    if ( protocol == 0x8008 ) return "ETHERTYPE_ATTSTANFORD";
    if ( protocol == 0x8010 ) return "ETHERTYPE_EXCELAN";
    if ( protocol == 0x8013 ) return "ETHERTYPE_SG_DIAG";
    if ( protocol == 0x8014 ) return "ETHERTYPE_SG_NETGAMES";
    if ( protocol == 0x8015 ) return "ETHERTYPE_SG_RESV";
    if ( protocol == 0x8016 ) return "ETHERTYPE_SG_BOUNCE";
    if ( protocol == 0x8019 ) return "ETHERTYPE_APOLLODOMAIN";
    if ( protocol == 0x802E ) return "ETHERTYPE_TYMSHARE";
    if ( protocol == 0x802F ) return "ETHERTYPE_TIGAN";
    if ( protocol == 0x8035 ) return "ETHERTYPE_REVARP";
    if ( protocol == 0x8036 ) return "ETHERTYPE_AEONIC";
    if ( protocol == 0x8037 ) return "ETHERTYPE_IPXNEW";
    if ( protocol == 0x8038 ) return "ETHERTYPE_LANBRIDGE";
    if ( protocol == 0x8039 ) return "ETHERTYPE_DSMD";
    if ( protocol == 0x803A ) return "ETHERTYPE_ARGONAUT";
    if ( protocol == 0x803B ) return "ETHERTYPE_VAXELN";
    if ( protocol == 0x803C ) return "ETHERTYPE_DECDNS";
    if ( protocol == 0x803D ) return "ETHERTYPE_ENCRYPT";
    if ( protocol == 0x803E ) return "ETHERTYPE_DECDTS";
    if ( protocol == 0x803F ) return "ETHERTYPE_DECLTM";
    if ( protocol == 0x8040 ) return "ETHERTYPE_DECNETBIOS";
    if ( protocol == 0x8041 ) return "ETHERTYPE_DECLAST";
    if ( protocol == 0x8044 ) return "ETHERTYPE_PLANNING";
    if ( protocol == 0x8048 ) return "ETHERTYPE_DECAM";
    if ( protocol == 0x8049 ) return "ETHERTYPE_EXPERDATA";
    if ( protocol == 0x805B ) return "ETHERTYPE_VEXP";
    if ( protocol == 0x805C ) return "ETHERTYPE_VPROD";
    if ( protocol == 0x805D ) return "ETHERTYPE_ES";
    if ( protocol == 0x8060 ) return "ETHERTYPE_LITTLE";
    if ( protocol == 0x8062 ) return "ETHERTYPE_COUNTERPOINT";
    if ( protocol == 0x8067 ) return "ETHERTYPE_VEECO";
    if ( protocol == 0x8068 ) return "ETHERTYPE_GENDYN";
    if ( protocol == 0x8069 ) return "ETHERTYPE_ATT";
    if ( protocol == 0x806A ) return "ETHERTYPE_AUTOPHON";
    if ( protocol == 0x806C ) return "ETHERTYPE_COMDESIGN";
    if ( protocol == 0x806D ) return "ETHERTYPE_COMPUGRAPHIC";
    if ( protocol == 0x807A ) return "ETHERTYPE_MATRA";
    if ( protocol == 0x807B ) return "ETHERTYPE_DDE";
    if ( protocol == 0x807C ) return "ETHERTYPE_MERIT";
    if ( protocol == 0x8080 ) return "ETHERTYPE_VLTLMAN";
    if ( protocol == 0x809B ) return "ETHERTYPE_ATALK";
    if ( protocol == 0x809F ) return "ETHERTYPE_SPIDER";
    if ( protocol == 0x80C6 ) return "ETHERTYPE_PACER";
    if ( protocol == 0x80C7 ) return "ETHERTYPE_APPLITEK";
    if ( protocol == 0x80D5 ) return "ETHERTYPE_SNA";
    if ( protocol == 0x80DD ) return "ETHERTYPE_VARIAN";
    if ( protocol == 0x80F2 ) return "ETHERTYPE_RETIX";
    if ( protocol == 0x80F3 ) return "ETHERTYPE_AARP";
    if ( protocol == 0x80F7 ) return "ETHERTYPE_APOLLO";
    if ( protocol == 0x8100 ) return "ETHERTYPE_VLAN";
    if ( protocol == 0x8102 ) return "ETHERTYPE_BOFL";
    if ( protocol == 0x8103 ) return "ETHERTYPE_WELLFLEET";
    if ( protocol == 0x812B ) return "ETHERTYPE_TALARIS";
    if ( protocol == 0x8130 ) return "ETHERTYPE_WATERLOO";
    if ( protocol == 0x8130 ) return "ETHERTYPE_HAYES";
    if ( protocol == 0x8131 ) return "ETHERTYPE_VGLAB";
    if ( protocol == 0x8137 ) return "ETHERTYPE_IPX";
    if ( protocol == 0x8138 ) return "ETHERTYPE_NOVELL";
    if ( protocol == 0x813F ) return "ETHERTYPE_MUMPS";
    if ( protocol == 0x8145 ) return "ETHERTYPE_AMOEBA";
    if ( protocol == 0x8146 ) return "ETHERTYPE_FLIP";
    if ( protocol == 0x8147 ) return "ETHERTYPE_VURESERVED";
    if ( protocol == 0x8148 ) return "ETHERTYPE_LOGICRAFT";
    if ( protocol == 0x8149 ) return "ETHERTYPE_NCD";
    if ( protocol == 0x814A ) return "ETHERTYPE_ALPHA";
    if ( protocol == 0x814C ) return "ETHERTYPE_SNMP";
    if ( protocol == 0x814F ) return "ETHERTYPE_TEC";
    if ( protocol == 0x8150 ) return "ETHERTYPE_RATIONAL";
    if ( protocol == 0x817D ) return "ETHERTYPE_XTP";
    if ( protocol == 0x817E ) return "ETHERTYPE_SGITW";
    if ( protocol == 0x8180 ) return "ETHERTYPE_HIPPI_FP";
    if ( protocol == 0x8181 ) return "ETHERTYPE_STP";
    if ( protocol == 0x818D ) return "ETHERTYPE_MOTOROLA";
    if ( protocol == 0x8191 ) return "ETHERTYPE_NETBEUI";
    if ( protocol == 0x8390 ) return "ETHERTYPE_ACCTON";
    if ( protocol == 0x852B ) return "ETHERTYPE_TALARISMC";
    if ( protocol == 0x8582 ) return "ETHERTYPE_KALPANA";
    if ( protocol == 0x86DB ) return "ETHERTYPE_SECTRA";
    if ( protocol == 0x86DD ) return "ETHERTYPE_IPV6";
    if ( protocol == 0x86DE ) return "ETHERTYPE_DELTACON";
    if ( protocol == 0x86DF ) return "ETHERTYPE_ATOMIC";
    if ( protocol == 0x8739 ) return "ETHERTYPE_RDP";
    if ( protocol == 0x873A ) return "ETHERTYPE_MICP";
    if ( protocol == 0x876B ) return "ETHERTYPE_TCPCOMP";
    if ( protocol == 0x876C ) return "ETHERTYPE_IPAS";
    if ( protocol == 0x876D ) return "ETHERTYPE_SECUREDATA";
    if ( protocol == 0x8808 ) return "ETHERTYPE_FLOWCONTROL";
    if ( protocol == 0x8809 ) return "ETHERTYPE_SLOW";
    if ( protocol == 0x880B ) return "ETHERTYPE_PPP";
    if ( protocol == 0x8820 ) return "ETHERTYPE_HITACHI";
    if ( protocol == 0x8847 ) return "ETHERTYPE_MPLS";
    if ( protocol == 0x8848 ) return "ETHERTYPE_MPLS_MCAST";
    if ( protocol == 0x8856 ) return "ETHERTYPE_AXIS";
    if ( protocol == 0x8863 ) return "ETHERTYPE_PPPOEDISC";
    if ( protocol == 0x8864 ) return "ETHERTYPE_PPPOE";
    if ( protocol == 0x8888 ) return "ETHERTYPE_LANPROBE";
    if ( protocol == 0x888e ) return "ETHERTYPE_PAE";
    if ( protocol == 0x9000 ) return "ETHERTYPE_LOOPBACK";
    if ( protocol == 0x9001 ) return "ETHERTYPE_XNSSM";
    if ( protocol == 0x9002 ) return "ETHERTYPE_TCPSM";
    if ( protocol == 0x9003 ) return "ETHERTYPE_BCLOOP";
    if ( protocol == 0xAAAA ) return "ETHERTYPE_DEBNI";
    if ( protocol == 0xFAF5 ) return "ETHERTYPE_SONIX";
    if ( protocol == 0xFF00 ) return "ETHERTYPE_VITAL";
    if ( protocol == 0xFFFF ) return "ETHERTYPE_MAX";
    if ( protocol == 0x1000 ) return "ETHERTYPE_TRAIL";
    return "Unassigned";
}
