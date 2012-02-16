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

use XML::XPath;
use Data::Dumper;

# If we get a description that matches one of these regular expressions, we
# will ignore it. That way we avoid bloat in our output code because the
# default description is "Unassigned".
my $treat_as_unassigned_type = qr/unassigned/i;
my $treat_as_unassigned_code = qr/no code/i;

my %icmp_codes;
my $xp = XML::XPath->new(filename => 'icmp-parameters.xml');

my $registry = $xp->find('/registry/registry[@id="icmp-parameters-types"]');
if ( $registry->size() != 1 ) {
    die "Don't know how to parse this file.";
}

my $nodeset = $registry->pop()->find('record');

foreach my $node ($nodeset->get_nodelist()) {
    my $value = $node->find('value');
    if ( $value->size() != 1 ) { next; }
    $value = $value->pop()->string_value;

    my $descr = $node->find('description');
    if ( $descr->size() != 1 ) { next; }
    $descr = $descr->pop()->string_value;

    if ( $value !~ /^\d+$/ || !$descr || $descr =~ $treat_as_unassigned_type ) { next; }
    $descr =~ s/\n+//g;
    $descr =~ s/[^[:print:]]//;
    $descr =~ s/ +/ /g;
    $icmp_codes{$value} = { descr => $descr };
}

undef $nodeset;
$registry = $xp->find('/registry/registry[@id="icmp-parameters-codes"]/registry');

if ( $registry->size() < 1 ) {
    die "Don't know how to parse this file.";
}

foreach my $code_node ($registry->get_nodelist()) {
    my $id = $code_node->getAttribute('id');

    if ( !defined $id || $id !~ /^icmp-parameters-codes-/ ) {
        die "Don't know how to parse this file.";
    }

    # Skip the codes that give a range.
    if ( $id !~ /^icmp-parameters-codes-(\d+)$/ ) {
        next;
    }
    $id = $1;

    $nodeset = $code_node->find('record');
    foreach my $node ($nodeset->get_nodelist()) {
        my $value = $node->find('value');
        if ( $value->size() != 1 ) { next; }
        $value = $value->pop()->string_value;

        my $descr = $node->find('description');
        if ( $descr->size() != 1 ) { next; }
        $descr = $descr->pop()->string_value;

        if ( $value !~ /^\d+$/ || !$descr || $descr =~ $treat_as_unassigned_code ) { next; }
        $descr =~ s/\n+//g;
        $descr =~ s/ +/ /g;

        if ( !exists $icmp_codes{$id} ) { next; }
        $icmp_codes{$id}->{codes}->{$value} = $descr;
    }
}

# It would be possible to create an array, but the array would have a lot of
# "holes", meaning you would have to allocate 255 entries but the vast
# majority would be set to NULL. The problem would be worse for the codes.
#foreach my $type ( sort{ $a <=> $b } ( keys( %icmp_codes ) ) ) {
#    my $name = $icmp_codes{$type}->{descr};
#    print qq{icmp_type_names[$type] = "$name"\n};
#}

# Instead we generate functions.
print qq#char *icmp_type_to_name( unsigned char type )\n{\n#;

foreach my $type ( sort{ $a <=> $b } ( keys( %icmp_codes ) ) ) {
    my $name = $icmp_codes{$type}->{descr};
    print qq#    if ( type == $type ) return "$name";\n#;
}

print qq#    return "Unassigned";\n}\n\n#;

print qq#char *icmp_code_to_name( unsigned char type, unsigned char code )\n{\n#;

foreach my $type ( sort{ $a <=> $b } ( keys( %icmp_codes ) ) ) {
    if ( !exists $icmp_codes{$type}->{codes} ) { next; }
    print qq#    if ( type == $type ) {\n#;
    foreach my $code ( sort{ $a <=> $b } ( keys( %{ $icmp_codes{$type}->{codes} } ) ) ) {
        my $name = $icmp_codes{$type}->{codes}->{$code};
        print qq#        if ( code == $code ) return "$name";\n#;
    }
    print qq#    }\n#;
}

print qq#    return "Unassigned";\n}\n\n#;

#die Dumper \%icmp_codes;
