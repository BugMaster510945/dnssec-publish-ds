package XymonDNSSEC::BBBuffer;

use strict;
use warnings;

# Tampon de sortie Hobbit : capture color_line/add_color pour rejeu conditionnel.
# sprintf est un passthrough direct vers le vrai bb (pour debug()). 
# Ne fonctionnera pas avec redwarn_error

sub new         { bless { buf => [], real_bb => $_[1] }, $_[0] }
sub color_line  { push @{$_[0]->{buf}}, ['color_line', @_[1..$#_]] }
sub color_print { push @{$_[0]->{buf}}, ['color_print', @_[1..$#_]] }
sub sprintf     { $_[0]->{real_bb}->sprintf(@_[1..$#_]) }

sub _replay {
    my ($self, $bb) = @_;
    for my $e (@{$self->{buf}}) {
        my $m = $e->[0];
        $bb->$m(@{$e}[1..$#$e]);
    }
}

1;
