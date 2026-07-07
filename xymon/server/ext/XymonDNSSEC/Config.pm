package XymonDNSSEC::Config;

use strict;
use warnings;

use Data::Dumper;
use Exporter qw(import);
use Hobbit;
use List::Util qw(min);
use Net::DNS::RR::DNSKEY;
use Storable qw(dclone);

our @EXPORT_OK = qw(
    load_probe_config
    collect_zone_names
    merge_zone_options
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

sub parse_duration {
    my ($value) = @_;
    return 0 unless defined $value;
    $value =~ s/^\s+|\s+$//g;
    
    if ($value =~ /^(\d+)([dhms])$/i) {
        my ($num, $unit) = ($1, lc($2));
        return $num if $unit eq 's';
        return $num * 60 if $unit eq 'm';
        return $num * 3600 if $unit eq 'h';
        return $num * 86400 if $unit eq 'd';
    }
    return int($value);  # Parse numérique brut
}

sub parse_bool_option_value {
    my ($value) = @_;
    return undef if !defined $value;
    my $v = lc($value);
    $v =~ s/^\s+|\s+$//g;
    return 1 if $v =~ /^(1|true|yes|on)$/;
    return 0 if $v =~ /^(0|false|no|off)$/;
    return undef;
}

sub parse_rrsig_delay {
    my ($value) = @_;
    return $value if ref($value) eq 'HASH';
    return { warn => undef, error => undef } if !defined $value;

    $value =~ s/^\s+|\s+$//g;
    return { warn => undef, error => undef } if $value eq q{};

    my ($warn_raw, $error_raw) = split /:/, $value, 2;
    my $warn = undef;
    my $error = undef;

    if (defined $warn_raw) {
        $warn_raw =~ s/^\s+|\s+$//g;
        $warn = parse_duration($warn_raw) if $warn_raw ne q{};
    }

    if (defined $error_raw) {
        $error_raw =~ s/^\s+|\s+$//g;
        $error = parse_duration($error_raw) if $error_raw ne q{};
    }

    return { warn => $warn, error => $error };
}

sub merge_rrsig_delay {
    my ($value, $defaults) = @_;

    my $v = parse_rrsig_delay($value);
    my $d = parse_rrsig_delay($defaults);

    return {
        warn  => defined $v->{warn}  ? $v->{warn}  : $d->{warn},
        error => defined $v->{error} ? $v->{error} : $d->{error},
    };
}

sub load_probe_config {
    my ($DEFAULTS, $path) = @_;
    my %DEFAULTS = %{ $DEFAULTS };

    my %cfg = %DEFAULTS;
    if (defined $path && $path ne q{} && -f $path) {
        my $yaml = eval { require YAML::Tiny; YAML::Tiny->read($path) };
        if ($yaml && $yaml->[0] && ref $yaml->[0] eq 'HASH') {
            $cfg{$_} = $yaml->[0]->{$_} for keys %{ $yaml->[0] };
        }
    }

    $cfg{resolver_timeout}                   = int($cfg{resolver_timeout});
    $cfg{zone_warn_if_no_nsec3}              = parse_bool_option_value($cfg{zone_warn_if_no_nsec3});
    $cfg{zone_require_permanent_cds_cdnskey} = parse_bool_option_value($cfg{zone_require_permanent_cds_cdnskey});
    $cfg{zone_parent_strip_labels}           = int($cfg{zone_parent_strip_labels});
    $cfg{zone_rrsig_delay}                   = merge_rrsig_delay($cfg{zone_rrsig_delay}, $DEFAULTS{zone_rrsig_delay});
    $cfg{zone_rollover_ds_propagation_delay} = merge_rrsig_delay($cfg{zone_rollover_ds_propagation_delay}, $DEFAULTS{zone_rollover_ds_propagation_delay});

    $cfg{nameservers} = [] if ref $cfg{nameservers} ne 'ARRAY';
    $cfg{server_options} = {} if ref $cfg{server_options} ne 'HASH';

    $cfg{allowed_algorithms} = $DEFAULTS{allowed_algorithms}
        if ref $cfg{allowed_algorithms} ne 'ARRAY';

    $cfg{allowed_algorithms} = normalize_allowed_algorithms($cfg{allowed_algorithms});
    # Calcul de la map des algos autorisés une seule fois dans la config fusionnée
    $cfg{allowed_algorithms_map} = { map { $_ => 1 } @{ $cfg{allowed_algorithms} } };

    return \%cfg;
}


sub collect_zone_names {
    my ($cfg, $cli_zones) = @_;

    $ENV{HOSTSCFG} = $cfg->{hosts_cfg} if (defined $cfg->{hosts_cfg} && $cfg->{hosts_cfg} ne q{} && -r $cfg->{hosts_cfg});

    my @entries;
    my %seen;

    my $list = Hobbit::grep('dnssec dnssec=*');
    foreach my $host (@$list) {
        my $zone = normalize_zone_input($host->{hostname});
        next if !defined $zone;
        next if $seen{$zone}++;

        my $opts = {};
        foreach my $tag (@{ $host->{tags} }) {
            if ($tag =~ /^dnssec(?:=(.*))?$/i) {
                $opts = parse_zone_options($1) if defined $1;
                push @entries, { zone => $zone, options => $opts };
                last;
            }
        }
    }

    for my $z (@{$cli_zones || []}) {
        my $zone = normalize_zone_input($z);
        next if !defined $zone;
        next if $seen{$zone}++;
        push @entries, { zone => $zone, options => {} };
    }

    return \@entries;
}

sub parse_zone_options {
    my ($raw) = @_;
    return {} if !defined $raw || $raw eq q{};

    my %OPT_MAP = (
        permanent_cds_cdnskey    => sub { ('require_permanent_cds_cdnskey', parse_bool_option_value($_[0])) },
        no_permanent_cds_cdnskey => sub { ('require_permanent_cds_cdnskey', !parse_bool_option_value($_[0])) },
        strip                    => sub { ('parent_strip_labels',           int($_[0])) },
        nsec3                    => sub { ('warn_if_no_nsec3',              parse_bool_option_value($_[0])) },
        nsec                     => sub { ('warn_if_no_nsec3',              !parse_bool_option_value($_[0])) },
        rrsig_delay              => sub { ('rrsig_delay',                   parse_rrsig_delay($_[0])) },
        rollover_ds_propagation_delay => sub { ('rollover_ds_propagation_delay', parse_rrsig_delay($_[0])) },
    );

    my %opts;
    for my $item (split /,/, lc($raw)) {
        $item =~ s/^\s+|\s+$//g;
        next if $item eq q{};

        my ($k, $v) = ($item, 1);
        if ($item =~ /^([^:]+):(.+)$/) {
            ($k, $v) = ($1, $2);
        }

        ($k, $v) = $OPT_MAP{$k}->($v) if exists $OPT_MAP{$k};     

        $opts{$k} = $v;
    }

    return \%opts;
}


sub normalize_allowed_algorithms {
    my ($values) = @_;

    my @out;
    my %seen;
    for my $v (@{ $values || [] }) {
        my $id;
        if ($v =~ /^\d+$/) {
            $id = int($v);
        } else {
            $id = eval { Net::DNS::RR::DNSKEY->algorithm($v) };
        }
        next if !defined $id || $id !~ /^\d+$/;
        next if $seen{$id}++;
        push @out, int($id);
    }

    return \@out;
}

sub merge_zone_options {
    my ($cfg, $zone_options) = @_;
    # Deep clone de tout $cfg
    my %merged = %{ dclone($cfg) };       
    # Override : chaque clé de zone_options devient zone_<clé> dans le merged
    if (defined $zone_options && ref $zone_options eq 'HASH') {
        for my $k (keys %$zone_options) {
            $merged{"zone_$k"} = $zone_options->{$k};
        }
    }

    if (exists $merged{zone_rrsig_delay}) {
        $merged{zone_rrsig_delay} = merge_rrsig_delay($merged{zone_rrsig_delay}, $cfg->{zone_rrsig_delay});
    }
    if (exists $merged{zone_rollover_ds_propagation_delay}) {
        $merged{zone_rollover_ds_propagation_delay} = merge_rrsig_delay($merged{zone_rollover_ds_propagation_delay}, $cfg->{zone_rollover_ds_propagation_delay});
    }

    return \%merged;
}

sub normalize_zone_input {
    my ($z) = @_;
    return undef if !defined $z;
    $z =~ s/^\s+|\s+$//g;
    $z =~ s/[;,]+$//;
    $z =~ s/\.+$//;
    return undef if $z eq q{};
    return lc($z);
}

1;
