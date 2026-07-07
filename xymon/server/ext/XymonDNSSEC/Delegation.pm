package XymonDNSSEC::Delegation;

use strict;
use warnings;

use Exporter qw(import);
use List::Util qw(min);
use Net::DNS;
use XymonDNSSEC::Reporter qw(:all);


our @EXPORT_OK = qw(
    compute_parent_zone
    fetch_delegation_from_parent
    build_zone_ns_list
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

sub compute_parent_zone {
    my ($ctx) = @_;

    my $strip = $ctx->{cfg}->{zone_parent_strip_labels} // 1;
    my $zone = $ctx->{zone};

    my @labels = split /\./, $zone;
    if (@labels <= $strip) {
        return (undef, sprintf('zone "%s" has %d label(s), cannot strip %d to find parent',
            $zone, scalar @labels, $strip));
    }

    my @parent_labels = @labels[$strip .. $#labels];
    return (join('.', @parent_labels), undef);
}

sub discover_parent_ns {
    my ($ctx, $parent) = @_;

    my ($packet, $ns_rrs, $err) = XymonDNSSEC::Resolver::query_rrset($ctx, $ctx->{recursive}, $parent, 'NS', 1);
    return (undef, "NS query for parent zone $parent failed: $err") if $err;
    return (undef, "No NS records found for parent zone $parent") if !@$ns_rrs;
       
    # Build IP map from additional section
    my %additional_ips;
    for my $rr ($packet->additional) {
        next unless $rr->type eq 'A' || $rr->type eq 'AAAA';
        push @{ $additional_ips{ lc($rr->name) =~ s/\.+$//r } }, $rr->address;
    }

    # Collect parent NS as {hostname, ips} pairs (additional first, then fallback resolve)
    my @parent_ns = map {
        my $h = lc($_->nsdname);
        my @ips = @{ $additional_ips{$h} || XymonDNSSEC::Resolver::resolve_host_ips($ctx, $ctx->{recursive}, $h) };
        { hostname => $h, ips => \@ips };
    } @$ns_rrs;

    return \@parent_ns;
}

sub fetch_delegation_from_parent {
    my ($ctx) = @_;

    if ($ctx->{zone_cache} && ref $ctx->{zone_cache} eq 'HASH' && keys %{$ctx->{zone_cache}}) {
        # --- Use cached parent delegation if available ---
        debug($ctx, "Using cached parent delegation for %s", $ctx->{zone});
        # Reconstruct RR objects from strings
        my @ns_rrs = map { Net::DNS::RR->new($_) } @{ $ctx->{zone_cache}->{ns_rrs} || [] };
        my @ds_rrs = map { Net::DNS::RR->new($_) } @{ $ctx->{zone_cache}->{ds_rrs} || [] };
        return (
            {
                ns_rrs    => \@ns_rrs,
                ds_rrs    => \@ds_rrs,
                glue_map  => $ctx->{zone_cache}->{glue_map},
                hints_map => $ctx->{zone_cache}->{hints_map},
                cache     => 1,
            }, undef
        );
    }

    # No cache, fetch data
    # --- Phase 2: Discover parent NS ---
    my ($parent_ns_list, $parent_ips_err) = discover_parent_ns($ctx, $ctx->{parent_zone});
    return (undef, $parent_ips_err) if( check_error($ctx, $parent_ips_err, "Parent NS discovery failed: %s", $parent_ips_err) );
    debug($ctx, "Parent NS: %d server(s)", scalar @$parent_ns_list);

    # Fetch delegation from parent and allow it to populate $ctx->{zone_cache}
    # Try each parent NS in order; use per-NS resolver so TSIG is applied when configured.
    my $last_err;
    for my $parent_ns (@$parent_ns_list) {
        next unless @{ $parent_ns->{ips} };
        my $resolver = XymonDNSSEC::Resolver::build_authoritative_resolver($ctx, $parent_ns->{ips}, $parent_ns->{hostname});

        # NS delegation: check answer then authority section
        my ($ns_packet, $ns_rrs, $ns_err) = XymonDNSSEC::Resolver::query_rrset($ctx, $resolver, $ctx->{zone}, 'NS');
        do { $last_err=$ns_err; next } if $ns_err;

        my @ns_rrs = grep { $_->type eq 'NS'} ($ns_packet->answer, $ns_packet->authority);
        return (undef, "No NS delegation records found for $ctx->{zone} on $parent_ns->{hostname}") if(!@ns_rrs);

        # Keep all additional IPs in hints_map; glue_map only marks in-zone NS.
        my (%glue_map, %hints_map);
        for my $rr ($ns_packet->additional) {
            next unless $rr->type eq 'A' || $rr->type eq 'AAAA';
            my $owner = lc($rr->name);
            push @{ $hints_map{$owner} }, $rr->address;
            push @{ $glue_map{$owner} }, $rr->address if (is_in_zone($owner, $ctx->{zone}));
        }

        # Limit DNS request if parent provide directly DS.
        my ($ds_packet, $ds_rrs, $ds_err);
        my @ds_rrs = grep { $_->type eq 'DS' } ($ns_packet->answer, $ns_packet->authority);
        if( !@ds_rrs ) {
            # DS records from parent
            ($ds_packet, $ds_rrs, $ds_err) = XymonDNSSEC::Resolver::query_rrset($ctx, $resolver, $ctx->{zone}, 'DS');
            return (undef, $ds_err) if $ds_err;
        }

        # Prepare return structure
        my $ds_list_ref = $ds_rrs // \@ds_rrs;

        # Compute a conservative min TTL from delegation NS and additional records
        my $min_ttl = min(map { $_->ttl } (@ns_rrs, grep { $_->type =~ /^A(?:AAA)?$/ } $ns_packet->additional));
        my $expiry = time() + ($min_ttl || $ctx->{cfg}->{cache_default_ttl} || 3600);

        # Populate zone-local cache in context (serialized as strings)
        $ctx->{zone_cache} = {
            ns_rrs  => [ map { $_->string } @ns_rrs ],
            ds_rrs  => [ map { $_->string } @{ $ds_list_ref || [] } ],
            glue_map  => \%glue_map,
            hints_map => \%hints_map,
            expiry => $expiry,
        };

        return ({
            ns_rrs    => \@ns_rrs,
            ds_rrs    => $ds_list_ref,
            glue_map  => \%glue_map,
            hints_map => \%hints_map,
        }, undef);
    }
    return (undef, $last_err // "No suitable parent NS found to fetch delegation for $ctx->{zone}");
}

sub build_zone_ns_list {
    my ($ctx) = @_;

    my @ns_list;
    my %seen;
    my $parent_ns_count = scalar @{ $ctx->{parent_delegation}->{ns_rrs}};
    my $cache_suffix = $ctx->{parent_delegation}->{cache} ? ' (cache)' : '';
    bbprint($ctx, "Parent delegation: %d NS%s", $parent_ns_count, $cache_suffix);
    for my $ns (sort { lc($a->nsdname) cmp lc($b->nsdname) } @{$ctx->{parent_delegation}->{ns_rrs}}) {
        my @ips;
        my $host = lc($ns->nsdname);
        next if $seen{$host}++;

        if (exists $ctx->{parent_delegation}->{hints_map}->{$host} && @{ $ctx->{parent_delegation}->{hints_map}->{$host} }) {
            @ips = @{ $ctx->{parent_delegation}->{hints_map}->{$host} };
        } else {
            my $resolved = XymonDNSSEC::Resolver::resolve_host_ips($ctx, $ctx->{recursive}, $host);
            @ips = @$resolved;
        }
        debug($ctx, "Parent delegation NS %s has IPs: %s (glue=%s)", $host, join(', ', @ips), exists $ctx->{parent_delegation}->{glue_map}->{$host} ? 'yes' : 'no');

        push @ns_list, { hostname => $host, ips => \@ips, is_glue => (exists $ctx->{parent_delegation}->{glue_map}->{$host} ? 1 : 0) };
    }

    return \@ns_list;
}

sub is_in_zone {
    my ($hostname, $zone_fqdn) = @_;
    my $h = lc($hostname);
    my $z = lc($zone_fqdn);
    return $h eq $z || $h =~ /\.\Q$z\E$/;

    my ($fqdn, $zone) = @_;
    return 0 unless defined $fqdn && defined $zone;
}

1;
