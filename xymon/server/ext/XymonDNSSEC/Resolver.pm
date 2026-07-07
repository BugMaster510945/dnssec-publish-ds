package XymonDNSSEC::Resolver;

use strict;
use warnings;

use Data::Dumper;
use Exporter qw(import);
use List::Util qw(max);
use Net::DNS;
use Net::DNS::SEC;
use XymonDNSSEC::Guard;
use XymonDNSSEC::BBBuffer;
use XymonDNSSEC::Reporter qw(:all);

our @EXPORT_OK = qw(
    build_recursive_resolver
    build_authoritative_resolver
    query_rrset
    resolve_host_ips
    prepare_rrsig_on_rrset
    check_rrsig_on_rrset
    synthesize_packet
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);


sub build_resolver {
    my (%args) = @_;

    my $r = Net::DNS::Resolver->new;
    $r->dnssec(1);
    $r->recurse($args{recurse});
    $r->udp_timeout($args{timeout});
    $r->tcp_timeout($args{timeout});
    $r->retrans($args{timeout});
    $r->retry(1);
    $r->defnames(0);
    $r->dnsrch(0);
    $r->searchlist('');
    $r->debug($args{debug});
    $r->nameservers(@{ $args{nameservers} }) if(ref $args{nameservers} eq 'ARRAY' && @{ $args{nameservers} });

    return $r;
}

sub build_recursive_resolver {
    my ($cfg) = @_;

    return build_resolver(
        recurse     => 1,
        timeout     => $cfg->{resolver_timeout},
        debug       => $cfg->{debug_dns},
        nameservers => $cfg->{nameservers},
    );
}

sub build_authoritative_resolver {
    my ($ctx, $server_ips, $server_name) = @_;

    my $r = build_resolver(
        recurse     => 0,
        timeout     => $ctx->{cfg}->{resolver_timeout},
        debug       => $ctx->{debug_dns},
        nameservers => $server_ips,
    );

    my $server_options = server_options_for($ctx, $server_name);
    # Ajout TSIG si défini dans les options
    if ($server_options && ref $server_options eq 'HASH' && $server_options->{tsig}) {
        my $tsig = $server_options->{tsig};
        if ($tsig->{name} && $tsig->{secret}) {
            debug($ctx, "Using TSIG for server %s: key name=%s, algorithm=%s", $server_name, $tsig->{name}, $tsig->{algorithm});
            # Vilain hack pour affecter la variable de tsig car tsig() ne fait le job qu'avec un fichier
            $r->{tsig_rr} = 
                Net::DNS::RR->new(
                    type      => 'TSIG',
                    name      => $tsig->{name},
                    algorithm => $tsig->{algorithm} || 'hmac-sha256',
                    key       => $tsig->{secret},
                )
            ;
        }
    }

    return $r;
}

sub query_rrset {
    my ($ctx, $resolver, $name, $type, $require_ad) = @_;

    my $packet = $resolver->send($name, $type, 'IN');
    return (undef, [], sprintf('DNS query %s %s failed: %s', $name, $type, $resolver->errorstring || 'unknown error')) if (!$packet);

    my $rcode = $packet->header->rcode;
    return ($packet, [], sprintf('DNS query %s %s returned rcode=%s', $name, $type, $rcode)) if ($rcode ne 'NOERROR');
    
    warn_error($ctx, $require_ad && !$packet->header->ad, "DNS query %s %s does not have AD flag", $name, $type);
   
    my @rrs = grep { $_->type eq $type } $packet->answer;
    return ($packet, \@rrs, undef);
}

# Construit un paquet synthétique (question $name/$type + rrset et RRSIG dans answer)
# à partir de records déjà obtenus (typiquement la section ADDITIONAL d'une réponse NS).
# Permet de réutiliser check_rrsig_on_rrset qui lit $packet->question et $packet->answer.
sub synthesize_packet {
    my ($name, $type, $rrs, $rrsigs) = @_;

    my $packet = Net::DNS::Packet->new($name, $type, 'IN');
    $packet->push(answer => $_) for @{ $rrs || [] };
    $packet->push(answer => $_) for @{ $rrsigs || [] };

    return $packet;
}

sub resolve_host_ips {
    my ($ctx, $resolver, $host_fqdn) = @_;

    my @ips;
    my %seen;

    for my $type ('A', 'AAAA') {
        my (undef, $rrs, $err) = query_rrset($ctx, $resolver, $host_fqdn, $type);
        next if $err;
        for my $rr (@$rrs) {
            my $ip = $rr->address;
            next if !$ip || $seen{$ip}++;
            push @ips, $ip;
        }
    }

    return \@ips;
}

sub server_options_for {
    my ($ctx, $server_name) = @_;

    return {} if ref $ctx->{cfg}->{server_options} ne 'HASH';

    my $key = lc($server_name || q{});

    return $ctx->{cfg}->{server_options}->{$key} if exists $ctx->{cfg}->{server_options}->{$key};
    return $ctx->{cfg}->{server_options}->{default} if exists $ctx->{cfg}->{server_options}->{default};
    return {};
}

sub prepare_rrsig_on_rrset {
    my ($ctx, $dnskey_rrs) = @_;

    my %keytags = map {
        $_->keytag => {
            dnskey => $_,
            is_ksk => (($_->flags & 257) == 257),
        }
    } @{ $dnskey_rrs || [] };

    foreach my $ds (@{ $ctx->{parent_delegation}->{ds_rrs} || [] }) {
        $keytags{ $ds->keytag }->{ds} = $ds;
    }

    $ctx->{current}->{rrsig_keys} = \%keytags;
}

sub check_rrsig_on_rrset {
    my ($ctx, $packet, $require_ksk_signer) = @_;
    
    my $rrtype = ($packet->question)[0]->qtype;
    my @rrsigs = grep { $_->type eq 'RRSIG' && uc($_->typecovered) eq uc($rrtype) } $packet->answer;
    return 0 if (check_error($ctx, !@rrsigs, "No RRSIG found for %s", $rrtype));

    my $nameprint = ($packet->question)[0]->qname ."/". $rrtype;
    my $keys      = $ctx->{current}->{rrsig_keys} || {};
    my @rrset_rrs = grep { uc($_->type) eq uc($rrtype) } $packet->answer;
    my $now       = time();
    my $ttl       = @rrset_rrs ? $rrset_rrs[0]->ttl : 0;

    # Guard restore : rétablit ctx->bb à la sortie de la fonction.
    # Guard replay  : rejoue le buffer si aucune RRSIG n'a passé.
    my @valid;
    my $real_bb    = $ctx->{bb};
    my $buf        = XymonDNSSEC::BBBuffer->new($real_bb);
    $ctx->{bb} = $buf;

    for my $rrsig (sort { $a->keytag <=> $b->keytag } @rrsigs) {
        my $keytag   = $rrsig->keytag;
        my $key      = $keys->{$keytag};

        # 1. Le signataire doit exister dans le DNSKEY set
        next if check_error($ctx, !$key, "RRSIG(%s) keytag=%d references unknown DNSKEY", $nameprint, $keytag);

        # 2. Validation cryptographique
        my $valid = eval { $rrsig->verify(\@rrset_rrs, $key->{dnskey}) };
        next if check_error($ctx, $@, "RRSIG(%s) keytag=%d crypto error: %s", $nameprint, $keytag, $@);
        next if check_error($ctx, !$valid, "RRSIG(%s) keytag=%d signature invalid", $nameprint, $keytag);

        # 3. Expiration : une signature expirée ou qui expirera avant TTL est invalide
        my $expiration = $rrsig->sigexpiration;
        next if check_error($ctx, ($now > $expiration), "RRSIG(%s) keytag=%d already expired %s ago", $nameprint, $keytag, human_duration($now - $expiration));
        next if check_error($ctx, ($now + $ttl > $expiration), "RRSIG(%s) keytag=%d expires in %s (< TTL %s): imminent expiry", $nameprint, $keytag, human_duration($expiration - $now), human_duration($ttl));

        # 4. Chaîne de confiance : si KSK obligatoire, le signataire doit être une KSK dans les DS
        if ($require_ksk_signer) {
            next if check_error($ctx, !$key->{is_ksk}, "RRSIG(%s) keytag=%d: signer is not a KSK", $nameprint, $keytag);
            next if check_error($ctx, !$key->{ds}, "RRSIG(%s) keytag=%d: KSK not covered by any DS", $nameprint, $keytag);
        }
        # On ne test pas la chaine complete de confiance car
        # les DNSKEY seront validés ici par rapport aux DS du parent
        # les autres entrées seront validés avec les DNSKEY validés
        # L'ordre ne sera peut-etre pas rescpecté (SOA,.. puis DNSKEY)
        # Mais ce sera tout de meme validé a postériori.

        debug($ctx, "RRSIG(%s) keytag=%d: valid, expires in %s", $nameprint, $keytag, human_duration($expiration - $now));
        push @valid, $expiration;
    }

    $ctx->{bb} = $real_bb;
    unless( @valid ) {
        $buf->_replay($real_bb);
        return 0
    }

    # Appliquer les seuils de renouvellement uniquement sur la RRSIG valide la plus futuriste.
    my $max_expiration = max @valid;

    my $delay = $ctx->{cfg}->{zone_rrsig_delay};
    return 1 if ref($delay) ne 'HASH';
    my $remaining = $max_expiration - $now;
    my $is_red = (defined $delay->{error} && $remaining < $delay->{error}) ? 1 : 0;
    my $is_yellow = (!$is_red && defined $delay->{warn} && $remaining < $delay->{warn}) ? 1 : 0;

    return 1 if
        check_error(
            $ctx,
            ($remaining < $delay->{error}),
            "RRSIG(%s) expires in %s (< renewal red threshold %s)",
            $nameprint,        
            human_duration($remaining),
            human_duration($delay->{error}),
        );

    warn_error(
        $ctx,
        ($remaining < $delay->{warn}),
        "RRSIG(%s) expires in %s (< renewal yellow threshold %s)",
        $nameprint,
        human_duration($remaining),
        human_duration($delay->{warn}),
    );

    
    return 1;
}

1;
