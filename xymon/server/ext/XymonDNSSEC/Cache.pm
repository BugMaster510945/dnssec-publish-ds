package XymonDNSSEC::Cache;

use strict;
use warnings;
use Data::Dumper;
use Exporter qw(import);
use Storable qw(nstore retrieve);
use Time::HiRes qw(time);
use XymonDNSSEC::Reporter qw(:all);

our @EXPORT_OK = qw(
    load_cache
    save_cache

    get_rollover_state
    record_rollover_start
    update_rollover_seen
    clear_rollover_state
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

sub resolve_cache_path {
    my ($cfg) = @_;
    return undef if !defined $cfg || !defined $cfg->{cache_file};
    return undef if $cfg->{cache_file} eq '-';
    my $file = $cfg->{cache_file} || 'xymon-ext-dnssec.cache';
    if ($file =~ m{^/}) {
        return $file;
    }
    my $dir = $ENV{XYMONTMP} || $ENV{TMP} || '/tmp';
    return "$dir/$file";
}

sub load_cache {
    my ($cfg) = @_;
    my $path = resolve_cache_path($cfg);
    print "[xymon-ext-dnssec] cache_path=" . (defined $path ? $path : "(undef)") . "\n" if($cfg->{debug});
    return {} unless defined $path && $path ne q{} && -f $path;
    my $cache = {};
    eval { $cache = retrieve($path) || {}; };
    if ($@) {
        warn sprintf("xymon-ext-dnssec: failed to read cache %s: %s\n", $path, $@);
        $cache = {};
    }

    print Dumper($cache) if($cfg->{debug});
    return $cache;
}

sub save_cache {
    my ($cfg, $cache) = @_;
    my $path = resolve_cache_path($cfg);
    return {} unless defined $path && $path ne q{} && defined $cache;
    eval { nstore($cache, $path); };
    if ($@) {
        warn sprintf("xymon-ext-dnssec: failed to save cache to %s: %s\n", $path, $@);
    }
}

sub get_rollover_state {
    my ($perm_cache, $zone, $fingerprint) = @_;
    return undef unless defined $perm_cache && ref $perm_cache eq 'HASH';
    my $zone_state = $perm_cache->{$zone} || {};
    return undef unless defined $zone_state->{rollover_cds_fingerprint} && $zone_state->{rollover_cds_fingerprint} eq ($fingerprint // '');
    return $zone_state;
}

sub record_rollover_start {
    my ($perm_cache, $zone, $fingerprint) = @_;
    return unless defined $perm_cache && ref $perm_cache eq 'HASH';
    my $now = time();
    $perm_cache->{$zone} = {
        rollover_cds_fingerprint => $fingerprint,
        rollover_first_seen      => $now,
        rollover_last_seen       => $now,
    };
}

sub update_rollover_seen {
    my ($perm_cache, $zone) = @_;
    return unless defined $perm_cache && ref $perm_cache eq 'HASH' && exists $perm_cache->{$zone};
    $perm_cache->{$zone}->{rollover_last_seen} = time();
}

sub clear_rollover_state {
    my ($perm_cache, $zone) = @_;
    return unless defined $perm_cache && ref $perm_cache eq 'HASH';
    delete $perm_cache->{$zone};
}

1;
