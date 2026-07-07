package XymonDNSSEC::ZoneState;

use strict;
use warnings;

use Exporter qw(import);
use Data::Dumper;
use Net::DNS;
use Net::DNS::RR::DNSKEY;
use XymonDNSSEC::Reporter qw(:all);
use XymonDNSSEC::Resolver;

our @EXPORT_OK = qw(
    check_rrsig_on_zonestate
    fetch_zone_state_from_server
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

sub check_rrsig_on_zonestate {
    my ($ctx) = @_;
    my $ok = 1;

    XymonDNSSEC::Resolver::prepare_rrsig_on_rrset($ctx, $ctx->{current}->{data}->{dnskey}->{rrs});

    for my $q (@{ $ctx->{current}->{data}->{checks} }) {
        my $dst = $q->{dst};
        next if !$dst->{packet};
        next if !@{ $dst->{rrs} || [] };

        $ok = 0 unless XymonDNSSEC::Resolver::check_rrsig_on_rrset($ctx, $dst->{packet}, $q->{require_ksk});
    }
    return $ok;
}

sub _run_zone_queries {
    my ($ctx, $resolver, $server_name, $server_ip_label, $state, $queries) = @_;

    for my $q (@{ $queries || [] }) {
        $state->{dnsquery}++;
        my $name = $q->{name} // $ctx->{zone};
        my $queryprint = $q->{name} ? sprintf('%s/%s', $q->{name}, $q->{query}) : $q->{query};
        ($q->{dst}->{packet}, $q->{dst}->{rrs}, my $err) = XymonDNSSEC::Resolver::query_rrset($ctx, $resolver, $name, $q->{query});

        if ($q->{check} eq 'strict') {
            return sprintf('%s failed on %s (%s): %s', $queryprint, $server_name, $server_ip_label, $err) if $err;
            return sprintf('%s empty on %s (%s)', $queryprint, $server_name, $server_ip_label) if !@{ $q->{dst}->{rrs} };
        } else {
            warn_error($ctx, $err, "%s query failed on %s (%s): %s", $queryprint, $server_name, $server_ip_label, $err);
        }
    }

    return undef;
}

sub fetch_zone_state_from_server {
    my ($ctx, $server_name, $server_ips) = @_;
    my $server_ip_label = join(', ', @$server_ips);
    my $state = {
        server => {
            name     => $server_name,
            ip_label => $server_ip_label,
            ips      => $server_ips,
        },
        dnsquery => 0,
        soa      => {},
        ns       => {},
        dnskey   => {},
        cds      => {},
        cdnskey  => {},
        nsec3    => {},
        glue     => {},
    };
    my $err;

    my $resolver = XymonDNSSEC::Resolver::build_authoritative_resolver($ctx, $server_ips, $server_name);

    my @queries = (
        { query => 'SOA',        check => 'strict', require_ksk => 0, dst => $state->{soa}     },
        { query => 'NS',         check => 'strict', require_ksk => 0, dst => $state->{ns}      },
        { query => 'DNSKEY',     check => 'strict', require_ksk => 1, dst => $state->{dnskey}  },
        { query => 'CDS',        check => 'warn',   require_ksk => 1, dst => $state->{cds}     },
        { query => 'CDNSKEY',    check => 'warn',   require_ksk => 1, dst => $state->{cdnskey} },
        { query => 'NSEC3PARAM', check => 'warn',   require_ksk => 0, dst => $state->{nsec3}   },
    );

    $err = _run_zone_queries($ctx, $resolver, $server_name, $server_ip_label, $state, \@queries);
    return $err if $err;

    # Glue dynamique : A/AAAA des NS in-bailiwick repérés par le parent (glue_map).
    # Optimisation : si le serveur a renvoyé du glue dans la section ADDITIONAL de la
    # réponse NS, on le réutilise (mode confiance par host) plutôt que de refaire des
    # requêtes A/AAAA. Un host totalement absent d'ADDITIONAL retombe sur des requêtes directes.
    my %add = _index_ns_additional($state->{ns}->{packet});

    my @glue_queries;
    for my $host (sort keys %{ $ctx->{parent_delegation}->{glue_map} || {} }) {
        if ($add{$host}) {
            # Réutilisation : on repackage les records d'ADDITIONAL dans un paquet synthétique
            # pour que la validation RRSIG existante (check_rrsig_on_zonestate) fonctionne.
            for my $type ('A', 'AAAA') {
                my $found = $add{$host}->{$type} or next;
                my $packet = XymonDNSSEC::Resolver::synthesize_packet($host, $type, $found->{rrs}, $found->{rrsigs});
                my $dst = $state->{glue}->{$host}->{$type} = { packet => $packet, rrs => $found->{rrs} };
                push @queries, { name => $host, query => $type, check => 'warn', require_ksk => 0, dst => $dst };
            }
        } else {
            # Repli : requêtes directes A/AAAA (comportement historique).
            push @glue_queries, { name => $host, query => $_, check => 'warn', require_ksk => 0, dst => ($state->{glue}->{$host}->{$_} = {}) } for ('A', 'AAAA');
        }
    }

    $err = _run_zone_queries($ctx, $resolver, $server_name, $server_ip_label, $state, \@glue_queries);
    return $err if $err;
    push @queries, @glue_queries;

    $state->{soa}->{mname}  = lc($state->{soa}->{rrs}->[0]->mname);
    $state->{soa}->{serial} = $state->{soa}->{rrs}->[0]->serial;

    # Liste plate des rrsets à valider (RRSIG), glue inclus
    $state->{checks} = \@queries;

    $ctx->{current}->{data} = $state;
   
    return (undef);
}

# Indexe la section ADDITIONAL d'une réponse NS par host/type.
# Retourne %add = ( host => { A => { rrs => [...], rrsigs => [...] }, AAAA => {...} } ).
# Les noms d'hôtes suivent la même normalisation que les clés de glue_map (lc, sans strip).
sub _index_ns_additional {
    my ($ns_packet) = @_;

    my %add;
    return %add if !$ns_packet;

    for my $rr ($ns_packet->additional) {
        my $type = $rr->type;
        if ($type eq 'A' || $type eq 'AAAA') {
            push @{ $add{ lc($rr->name) }->{$type}->{rrs} }, $rr;
        } elsif ($type eq 'RRSIG') {
            my $covered = $rr->typecovered;
            next unless $covered eq 'A' || $covered eq 'AAAA';
            push @{ $add{ lc($rr->name) }->{$covered}->{rrsigs} }, $rr;
        }
    }

    return %add;
}

1;
