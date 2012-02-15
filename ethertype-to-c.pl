#!/usr/local/bin/perl

#
# Copyright (c) 2012, Yahoo! Inc All rights reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     Redistributions of source code must retain the above copyright notice,
#     this list of conditions and the following disclaimer.  Redistributions
#     in binary form must reproduce the above copyright notice, this list
#     of conditions and the following disclaimer in the documentation and/or
#     other materials provided with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS
# BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY,
# OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
# THE POSSIBILITY OF SUCH DAMAGE.
#
# Author: John Eaglesham
#
# This file is meant to parse the output of:
#  http://www.iana.org/assignments/icmp-parameters/icmp-parameters.xml
# And turn it into a semi-useful C code.
#

use warnings;
use strict;

use Data::Dumper;

my $fh;

open( $fh, '<', '/usr/include/net/ethernet.h' ) || die "Failed to open /usr/include/net/ethernet.h: $!";

print qq#char *ether_protocol_to_name( unsigned short protocol )\n{\n#;
while( my $l = <$fh> ) {
    # BSD style.
    if ( $l =~ /^\s*#define\s+(ETHERTYPE_[[:graph:]]+)\s+(0x[[:xdigit:]]+)/ ) {
        next if ord( $2 ) > 65535;
        print qq#    if ( protocol == $2 ) return "$1";\n#;

    # Linux style.
    } elsif ( $l =~ /^\s+(IPPROTO_[[:graph:]]+)\s+=\s+(0x[[:xdigit:]]+)/ ) {
        next if ord( $2 ) > 65535;
        print qq#    if ( protocol == $2 ) return "$1";\n#;
    }
}
print qq#    return "Unassigned";\n}\n#;
