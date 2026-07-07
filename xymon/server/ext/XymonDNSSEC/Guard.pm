package XymonDNSSEC::Guard;

use strict;
use warnings;

# Package Guard permet d'emuler le defer en go
sub new { 
    bless \$_[1], $_[0] 
}

sub DESTROY { 
    ${$_[0]}->() 
}

1;