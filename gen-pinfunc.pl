#!/usr/bin/env perl
use strict;
use warnings;

my $input;

if (@ARGV) {
    my $file = shift @ARGV;
    open my $fh, '<', $file or die "$0: cannot open $file: $!\n";
    local $/;
    $input = <$fh>;
    close $fh;
} else {
    local $/;
    $input = <STDIN>;
}

my $prefix;
if ($input =~ /mtk_pins_([a-z0-9_]+)\s*\[\s*\]/i) {
    $prefix = uc $1;
} elsif ($input =~ /#ifndef\s+__PINCTRL_MTK_([A-Z0-9_]+)_H/) {
    $prefix = uc $1;
} else {
    die "$0: cannot determine chip prefix\n";
}

my $preamble = '';
if ($input =~ /\A(.*?)(?=#ifndef)/s) {
    $preamble = $1;
    $preamble .= "\n" if length($preamble) && $preamble !~ /\n\z/;
}

my @pins;
pos($input) = 0;
while ($input =~ /MTK_PIN\s*\(/g) {
    my $open = index($input, '(', $-[0]);
    next unless $open >= 0;

    my $close = matching_paren($input, $open);
    next unless defined $close;

    my $body = substr($input, $open + 1, $close - $open - 1);

    if ($body =~ /\A\s*(\d+)\s*,\s*"([^"]*)"/s) {
        my $num = $1;
        my @funcs;

        while ($body =~ /MTK_FUNCTION\s*\(\s*(\d+)\s*,\s*"([^"]*)"\s*\)/g) {
            push @funcs, [ $1, $2 ];
        }

        push @pins, { num => $num, funcs => \@funcs } if @funcs;
    }

    pos($input) = $close + 1;
}

@pins = sort { $a->{num} <=> $b->{num} } @pins;

print $preamble;
print "#ifndef __${prefix}_PINFUNC_H\n";
print "#define __${prefix}_PINFUNC_H\n\n";
print "#include <dt-bindings/pinctrl/mt65xx.h>\n\n";

for my $pin (@pins) {
    my $num = $pin->{num};
    my @funcs = sort { $a->[0] <=> $b->[0] } @{ $pin->{funcs} };

    for my $f (@funcs) {
        my ($val, $name) = @$f;
        my $fn = sanitize_func($name);
        print "#define ${prefix}_GPIO${num}__FUNC_${fn}\t(MTK_PIN_NO(${num}) | ${val})\n";
    }

    print "\n";
}

print "#endif /* __${prefix}_PINFUNC_H */\n";

sub sanitize_func {
    my ($name) = @_;

    # A_FUNC_DIN[3] -> A_FUNC_DIN_3
    $name =~ s/\[(\d+)\]/_$1/g;
    $name =~ s/[^A-Za-z0-9_]/_/g;
    $name =~ s/_+/_/g;
    $name =~ s/^_+//;
    $name =~ s/_+$//;

    return $name;
}

sub matching_paren {
    my ($s, $open) = @_;

    my $depth  = 0;
    my $in_str = 0;
    my $esc    = 0;

    for (my $i = $open; $i < length($s); $i++) {
        my $c = substr($s, $i, 1);

        if ($in_str) {
            if ($esc) {
                $esc = 0;
            } elsif ($c eq '\\') {
                $esc = 1;
            } elsif ($c eq '"') {
                $in_str = 0;
            }
            next;
        }

        if ($c eq '"') {
            $in_str = 1;
            next;
        }

        if ($c eq '(') {
            $depth++;
        } elsif ($c eq ')') {
            $depth--;
            return $i if $depth == 0;
        }
    }

    return undef;
}
