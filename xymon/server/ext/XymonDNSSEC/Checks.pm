package XymonDNSSEC::Checks;

use strict;
use warnings;

use Data::Dumper;
use Exporter qw(import);
use Net::DNS::RR::DS;
use Net::DNS::RR::DNSKEY;
use Storable qw(dclone);
use Time::HiRes qw(time);

use XymonDNSSEC::Guard;
use XymonDNSSEC::Reporter qw(:all);
use XymonDNSSEC::Cache qw(:all);
use XymonDNSSEC::ZoneState;
use XymonDNSSEC::Delegation;

use constant COLOR_TABLE_GYR => [qw(green yellow red)];
use constant COLOR_TABLE_GYY => [qw(green yellow yellow)];
use constant COLOR_TABLE_YYR => [qw(yellow yellow red)];

our @EXPORT_OK = qw(
    run_zone_checks
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);


sub run_zone_checks {
    my ($ctx) = @_;

    # --- Phase 1: Compute parent zone ---
    my ($parent_zone, $parent_zone_err) = XymonDNSSEC::Delegation::compute_parent_zone($ctx);
    return if( check_error($ctx, $parent_zone_err, "Cannot determine parent zone: %s", $parent_zone_err) );
    debug($ctx, "Computed parent zone: %s", $parent_zone);
    $ctx->{parent_zone} = $parent_zone;

    # --- Phase 2: Fetch delegation from parent ---
    my ($delegation, $delegation_err) = XymonDNSSEC::Delegation::fetch_delegation_from_parent($ctx);
    return if( check_error($ctx, $delegation_err, "Delegation query failed: %s", $delegation_err) );
    return if( check_error($ctx, !@{$delegation->{ds_rrs}}, "No DS at parent zone (%s): zone not in DNSSEC chain", $parent_zone) );
    $ctx->{parent_delegation} = $delegation;

    # --- Phase 3: Check DS from parent for unsupported algorithms ---
    check_parent_ds_algorithms($ctx);

    # --- Phase 4: Build zone NS list ---
    my $ns_list = XymonDNSSEC::Delegation::build_zone_ns_list($ctx);
    return if( check_error($ctx, !@$ns_list, "No NS found in delegation for %s", $ctx->{zone}) );
    bbprint($ctx, ""); # Saute une ligne

    # --- Phase 5: Clean up zone_status for NS no longer in ns_list ---
    my %active_ns = map { $_->{hostname} => 1 } @$ns_list;
    for my $name (keys %{ $ctx->{zone_status} }) {
        delete $ctx->{zone_status}->{$name} unless $active_ns{$name};
    }

    # my $ns_passed = 0;
    # my $ns_total  = scalar @{$ns_list};
    $ctx->{ns_keytag_collection} = { by_ns => {}, cds => {}, cdnskey => {}, dnskey => {}};
       
    # --- Phase 6: Advanced tests on each NS ---
    for my $ns (sort { lc($a->{hostname}) cmp lc($b->{hostname}) } @$ns_list) {
        my $name = $ns->{hostname};
        my $ips  = $ns->{ips} || [];
        $ctx->{zone_status}->{$name} //= {};
        $ctx->{current} = {
            status => $ctx->{zone_status}->{$name}
        };

        next if( redwarn_error($ctx, !@$ips, "No resolved IPs for NS %s", $name) );
        bbprint($ctx, "%s (%s)", $name, join(', ', @$ips));
        my @defer = ( XymonDNSSEC::Guard->new(sub { bbprint($ctx, ""); }) ); # Saute une ligne

        my $t0 = time();
        my $err = XymonDNSSEC::ZoneState::fetch_zone_state_from_server($ctx, $name, $ips);
        next if redwarn_error($ctx, $err, "Failed to fetch zone state from %s: %s", $name, $err);
        my $data = $ctx->{current}->{data};
        $data->{time} = time() - $t0;
        $data->{timeperquery} = $data->{time} / $data->{dnsquery};

        (my $rrd_ns = $name) =~ s/,/_/g;
        $ctx->{trends}->sprintf("[dnssec,nstime,%s.rrd]\n", $rrd_ns);
        $ctx->{trends}->sprintf("DS:elapsed:GAUGE:600:U:U %.6f\n", $data->{timeperquery});

        # Add query time at the end
        push @defer, XymonDNSSEC::Guard->new(sub { bbprint($ctx, "Time: %s (sum: %s)", human_duration($data->{timeperquery}, 1), human_duration($data->{time}, 1)); });

        bbprint($ctx, "SOA serial=%d mname=%s", $data->{soa}->{serial}, $data->{soa}->{mname});

        # --- Step 1: Check all data validity ---
        next unless XymonDNSSEC::ZoneState::check_rrsig_on_zonestate($ctx);

        prepare_dnskey($ctx);
        populate_ns_keytag_collection($ctx, $name);
        check_zone_algorithms($ctx);
        
        # --- Step: Check rollover 
        check_rollover($ctx);

        # --- Step: Check NS set vs parent delegation ---
        check_ns_set_vs_parent($ctx);

        # --- Step: Check NSEC3PARAM compliance ---
        check_nsec3param($ctx);

        # --- Step: Check glue ---
        check_glue_coherence($ctx);
    }

    # --- Post-Phase 6: Check consistency across all NS ---
    check_dnskey_cds_cdnskey_consistency_across_ns($ctx);
    
    # Summary: x/y DNS servers fully compliant (color decided in one expression)
    # color_line($ctx, $ns_passed == 0 ? 'red' : ($ns_passed == $ns_total ? 'green' : 'yellow'),
    #     "%d/%d DNS servers fully compliant", $ns_passed, $ns_total);
    bbprint($ctx, ""); # Saute une ligne    
}

sub prepare_dnskey {
    my ($ctx) = @_;
    my %dnskey;

    my %hash_types = (
        map({ (eval { $_->digtype } // '') => 1 } @{ $ctx->{parent_delegation}->{ds_rrs} // [] }),
        # Non on va regarder que le parent 
        # map({ (eval { $_->digtype } // '') => 1 } @{ $ctx->{current}->{data}->{cds}->{rrs} // [] }),
    );
    delete $hash_types{''};
    my @hash_types = sort { $a <=> $b } keys %hash_types;
    @hash_types = (Net::DNS::RR::DS->digtype('SHA-256')) unless @hash_types; # fallback SHA-2 (SHA-256)

    my %rr_sources = (
        ds      => [ @{ $ctx->{parent_delegation}->{ds_rrs} // [] } ],
        cds     => [ @{ $ctx->{current}->{data}->{cds}->{rrs} // [] } ],
        # On ne filtre pas les KSK, on le fait apres car on a besoin des ZSK pour un autre usage
        dnskey  => [ @{ $ctx->{current}->{data}->{dnskey}->{rrs} // [] } ],
        cdnskey => [ @{ $ctx->{current}->{data}->{cdnskey}->{rrs} // [] } ],
    );

    for my $type (keys %rr_sources) {
        for my $rr (@{ $rr_sources{$type} }) {
            my @rrs_as_ds;
            if ($type eq 'ds' || $type eq 'cds') {
                @rrs_as_ds = ($rr);
            } else {
                @rrs_as_ds = grep { defined $_ }
                    map { eval { Net::DNS::RR::DS->create($rr, digtype => $_) } }
                    @hash_types;
            }

            for my $rr_as_ds (@rrs_as_ds) {
                my $composite = _dnskey_entry_id($rr_as_ds);
                next unless defined $composite;

                $dnskey{$composite} ||= { 
                    keytag => $rr->keytag,
                    algo_num => $rr->algorithm,
                    algo_str => $rr->algorithm('MNEMONIC'),
                };

                if( $type ne 'dnskey' || ($rr->flags & 257) == 257) {
                    $dnskey{$composite}->{$type} = $rr;
                }
                # Always add to all_dnskey if DNSKEY
                $dnskey{$composite}->{all_dnskey} = $rr if ($type eq 'dnskey');
            }
        }
    }

    $ctx->{current}->{dnskey} = \%dnskey;
}

sub populate_ns_keytag_collection {
    my ($ctx, $ns_name) = @_;
    my $dnskey_hash = $ctx->{current}->{dnskey} // {};

    $ctx->{ns_keytag_collection}->{by_ns}->{$ns_name} //= {};
    for my $composite_key (keys %$dnskey_hash) {
        my $entry = $dnskey_hash->{$composite_key};
        my $newentry = {
            keytag   => $entry->{keytag},
            algo_num => $entry->{algo_num},
            algo_str => $entry->{algo_str},
        };

        # Determine type: which of cds, cdnskey, dnskey is present
        # and build type flags for by_ns index
        $ctx->{ns_keytag_collection}->{by_ns}->{$ns_name}->{$composite_key} //= {};
        foreach my $type (qw(cds cdnskey dnskey)) {
            my $overry_type = $type eq 'dnskey' ? 'all_dnskey' : $type;
            $ctx->{ns_keytag_collection}->{by_ns}->{$ns_name}->{$composite_key}->{$type} = 0;
            if ($entry->{$overry_type}) {
                $ctx->{ns_keytag_collection}->{$type}->{$composite_key} = $newentry;
                $ctx->{ns_keytag_collection}->{by_ns}->{$ns_name}->{$composite_key}->{$type} = 1;
            }
        }
    }
}

# Chronologie Rollover
#
# DS=K1, DNSKEY=K1, CDS=K1|-
# Generation/Publication K2
# DS=K1, DNSKEY=K1+K2, CDS=K1|-
# Attente publish-safety(1h)
# DS=K1, DNSKEY=K1+K2, CDS=K2
# Detection par le parent
# DS=K2, DNSKEY=K1+K2, CDS=K2
# Detection prise en compte du parent (+delai)
# DS=K2, DNSKEY=K2, CDS=K2|-
sub check_rollover {
    my ($ctx) = @_;
    my $now = time();
    my $status = $ctx->{current}->{status};
    my $require_signals = $ctx->{cfg}->{zone_require_permanent_cds_cdnskey} // 0;
    my $ds_delay = $ctx->{cfg}->{zone_rollover_ds_propagation_delay} || {};   
    my $dnskey_hash = $ctx->{current}->{dnskey} // {};

    my $has_any_signal = grep {
        ($dnskey_hash->{$_}->{cds} || $dnskey_hash->{$_}->{cdnskey})
    } keys %$dnskey_hash;
    my $no_signal_any_kt = $has_any_signal ? 0 : 1;
    
    my $t1_ok = 1;  # T1: DS => DNSKEY
    my $t2_ok = 1;  # T2: CDS/CDNSKEY => DNSKEY
    # my $t3_ok = 1;  # T3: DNSKEY present, DS absent (rollover)
    my $t2_has_any = 0;  # Track if there are any entries
    my $t3_has_any = 0;
    
    # --- Tests par keytag ---
    for my $idx (keys %$dnskey_hash) {
        my $kt = $dnskey_hash->{$idx}->{keytag};
        my $algo_num = $dnskey_hash->{$idx}->{algo_num};
        my $algo_str = $dnskey_hash->{$idx}->{algo_str};
        my $in_parent = $dnskey_hash->{$idx}->{ds} ? 1 : 0;
        my $in_child  = $dnskey_hash->{$idx}->{dnskey} ? 1 : 0;
        my $in_cds    = $dnskey_hash->{$idx}->{cds} ? 1 : 0;
        my $in_cdnskey = $dnskey_hash->{$idx}->{cdnskey} ? 1 : 0;
        my $in_signal = ($in_cds || $in_cdnskey) ? 1 : 0;
        
        # T1: DS: present, DNSKEY: absent
        # Chaque DS parent doit avoir une DNSKEY correspondante
        # Ce cas ne doit jamais se produire
        if ($in_parent) {
            $t1_ok = 0 if warn_error($ctx, !$in_child, "DS keytag=%d algo=%d(%s): no matching DNSKEY in zone", $kt, $algo_num, $algo_str);
            debug($ctx, "DS keytag=%d algo=%d(%s): matching DNSKEY found", $kt, $algo_num, $algo_str) if $in_child;
        }

        # T2: CDS/CDNSKEY: present, DNSKEY: absent
        # tout CDS/CDNSKEY present doit avoir sa DNSKEY correspondante
        # Ce cas ne doit jamais se produire
        if ($in_signal) {
            $t2_has_any = 1;
            $t2_ok = 0 if warn_error($ctx, !$in_child, "CDS/CDNSKEY keytag=%d algo=%d(%s): no matching DNSKEY in zone", $kt, $algo_num, $algo_str);
            debug($ctx, "CDS/CDNSKEY keytag=%d algo=%d(%s): matching DNSKEY found", $kt, $algo_num, $algo_str) if $in_child;
        }

        # T3: DS: absent, DNSKEY: present (rollover)
        if ($in_child && !$in_parent) {
            $t3_has_any = 1;
            if ($in_signal) { # Début du rollover, demande d'ajout de clé
                _set_status($status, $idx, 'absent_parent', $now);
                _del_status($status, $idx, 'absent_parent_no_signal');

                my $started = _get_status($status, $idx, 'absent_parent');
                my $age = $now - $started;           
                my $age_str = human_duration($age);
                color_print(
                    $ctx,
                    _age_to_color($age, $ds_delay, COLOR_TABLE_GYY) , # Status
                    _age_to_color($age, $ds_delay, COLOR_TABLE_YYR) , # Line
                    "DNSKEY keytag=%d algo=%d(%s): no matching DS published (rollover for %s)", $kt, $algo_num, $algo_str, $age_str);
            } else {
                # Prépublication (avant le début du rollover) (CDS=Kother|-)
                # Fin du rollover (clé à dé-publier) (CDS=Kother|-)
                # cas spécial si CDS/CDNSKEY=vide --> pas de changement (CDS=-)
                # Ici on peut gérer un allow_oprhan_key
                _set_status($status, $idx, 'absent_parent_no_signal', $now);
                _del_status($status, $idx, 'absent_parent');

                my $started = _get_status($status, $idx, 'absent_parent_no_signal');
                my $age = $now - $started;           
                my $age_str = human_duration($age);
                color_print(
                    $ctx,
                    _age_to_color($age, $ds_delay, COLOR_TABLE_GYY) , # Status
                    _age_to_color($age, $ds_delay, COLOR_TABLE_YYR) , # Line
                    "DNSKEY keytag=%d algo=%d(%s): no matching DS published (pre-publish or end of rollover for %s)", $kt, $algo_num, $algo_str, $age_str);
            }
        } else {
            # T3 resolu: des que parent revient ou si la key n'est plus en enfant.
            _del_status($status, $idx, 'absent_parent_no_signal');
            _del_status($status, $idx, 'absent_parent');
        }

    }
    
    # Print success messages if checks passed
    color_line($ctx, 'green', "All DS keytags are covered by DNSKEY") if($t1_ok);   
    color_line($ctx, 'green', "All CDS/CDNSKEY keytags are covered by DNSKEY") if($t2_has_any && $t2_ok);
    color_line($ctx, 'green', "No KSK DNSKEY rollover in progress") unless $t3_has_any;
    
    # Global: vérifier zéro CDS/CDNSKEY si require_signals
    warn_error($ctx, $no_signal_any_kt, "No CDS or CDNSKEY published (required by policy)") if ($require_signals);

    tidy_status($ctx);
}

# Helpers pour status minimal
sub _set_status {
    my ($status, $keytag, $rule, $now) = @_;
    $status->{$keytag} ||= {};
    $status->{$keytag}->{$rule} = $now
        unless exists $status->{$keytag}->{$rule};
}

sub _get_status {
    my ($status, $keytag, $rule) = @_;
    return undef unless exists $status->{$keytag};
    return undef unless exists $status->{$keytag}->{$rule};
    return $status->{$keytag}->{$rule};
}

sub _del_status {
    my ($status, $keytag, $rule) = @_;
    return unless exists $status->{$keytag}->{$rule};
    delete $status->{$keytag}->{$rule};
    delete $status->{$keytag} unless keys %{ $status->{$keytag} };
}

sub tidy_status {
    my ($ctx) = @_;
    my $status = $ctx->{current}->{status};
    my $dnskey_hash = $ctx->{current}->{dnskey};

    return unless ref($status) eq 'HASH';
    return unless ref($dnskey_hash) eq 'HASH';

    for my $composite (keys %$status) {
        my $entry = $status->{$composite};
        delete $status->{$composite} and next unless defined $entry;
        delete $status->{$composite} and next unless ref($entry) eq 'HASH';
        delete $status->{$composite} and next unless exists $dnskey_hash->{$composite};
        delete $status->{$composite} unless keys %$entry;
    }
}


sub _age_to_color {
    my ($age, $thresholds, $colors) = @_;

    return $colors->[2] unless defined $age;
    return $colors->[2] if $age >= $thresholds->{error};
    return $colors->[1] if $age >= $thresholds->{warn};
    return $colors->[0];
}

sub _dnskey_entry_id {
    my ($rr) = @_;

    my $type = eval { uc($rr->type || '') };
    return undef unless $type eq 'DS' || $type eq 'CDS';

    my $hash4 = lc($rr->digest);
    $hash4 =~ s/[^0-9a-f]//g;
    $hash4 .= '0000';
    $hash4 = substr($hash4, 0, 4);
    return join('-', $rr->keytag, $rr->algorithm, $hash4);
}

sub check_parent_ds_algorithms {
    my ($ctx, $ds_rrs) = @_;
    my @ds_rrs = @{$ctx->{parent_delegation}->{ds_rrs}};
    my $cache_suffix = $ctx->{parent_delegation}->{cache} ? ' (cache)' : '';
    my $allowed = $ctx->{cfg}->{allowed_algorithms_map};
    for my $ds (sort { $a->keytag <=> $b->keytag } @ds_rrs) {
        my $algo = $ds->algorithm;
        my $algo_str = Net::DNS::RR::DNSKEY->algorithm($algo) || $algo;
        my $keytag = $ds->keytag;
        if ($allowed->{$algo}) {
            color_line($ctx, 'green', "Parent DS keytag=%d algo=%d(%s)%s", $keytag, $algo, $algo_str, $cache_suffix);
        } else {
            color_line($ctx, 'yellow', "Parent DS keytag=%d algo=%d(%s): NOT allowed%s", $keytag, $algo, $algo_str, $cache_suffix);
        }
    }
}

sub check_zone_algorithms {
    my ($ctx) = @_;
    my $dnskey_hash = $ctx->{current}->{dnskey} // {};
    my $allowed = $ctx->{cfg}->{allowed_algorithms_map};

    for my $type (qw(dnskey cds cdnskey)) {
        my $all_ok = 1;
        
        for my $composite (keys %$dnskey_hash) {
            my $entry = $dnskey_hash->{$composite};
            next unless $entry->{$type};
            
            my $algo = $entry->{algo_num};
            my $algo_str = $entry->{algo_str};
            my $keytag = $entry->{keytag};
            
            $all_ok = 0 if warn_error($ctx, !$allowed->{$algo}, "%s keytag=%d algo=%d(%s): NOT allowed", uc($type), $keytag, $algo, $algo_str);            
        }
        
        if ($all_ok) {
            my @keytags = sort { $a <=> $b } 
                map { $_->{keytag} } 
                grep { $_->{$type} } 
                values %$dnskey_hash;
            color_line($ctx, 'green', "All %s algorithms are allowed", uc($type)) if @keytags;
        }
    }
}

sub check_nsec3param {
    my ($ctx) = @_;
    my $ok     = 1;
    my $warn   = $ctx->{cfg}->{zone_warn_if_no_nsec3} // 1;
    my $n3_rrs = $ctx->{current}->{data}->{nsec3}->{rrs} || [];

    if (!@$n3_rrs) {
        if ($warn) {
            color_line($ctx, 'yellow', "No NSEC3PARAM found");
            return 0;
        }
        color_line($ctx, 'clear', "No NSEC3PARAM found");
        return $ok;
    }

    for my $nsec3 (@$n3_rrs) {
        my $iterations = $nsec3->iterations // 0;
        my $salt = $nsec3->salt // '';

        $ok = 0 if check_error($ctx, $iterations > 100, "NSEC3PARAM iterations=%d > 100: violates RFC 9276", $iterations);
        $ok = 0 if warn_error($ctx, $iterations > 0 && $iterations <= 100, "NSEC3PARAM iterations=%d > 0: not RFC 9276 compliant (should be 0)", $iterations);
        debug($ctx, "NSEC3PARAM iterations=%d: RFC 9276 compliant", $iterations) if $iterations == 0;
     
        $ok = 0 if warn_error($ctx, $salt ne '' && $salt ne '-', "NSEC3PARAM salt is not empty: not RFC 9276 compliant");
        debug($ctx, "NSEC3PARAM salt empty: RFC 9276 compliant") if $salt eq '' || $salt eq '-';
    }

    color_line($ctx, 'green', "NSEC3PARAM is RFC 9276 compliant") if $ok;
    return $ok;
}

sub check_ns_set_vs_parent {
    my ($ctx) = @_;
    my $ok = 1;

    my $parent_ns_rrs = $ctx->{parent_delegation}->{ns_rrs} || [];
    my $server_ns_rrs = $ctx->{current}->{data}->{ns}->{rrs} || [];

    my %parent_set = map { lc($_->nsdname) =~ s/\.+$//r => 1 } @$parent_ns_rrs;
    my %server_set = map { lc($_->nsdname) =~ s/\.+$//r => 1 } @$server_ns_rrs;

    for my $ns (sort keys %server_set) {
        $ok = 0 if warn_error($ctx, !$parent_set{$ns}, "Zone NS %s not found in parent delegation", $ns);
    }

    for my $ns (sort keys %parent_set) {
        $ok = 0 if warn_error($ctx, !$server_set{$ns}, "Parent NS %s missing from zone NS set", $ns);
    }

    color_line($ctx, 'green', "NS set matches parent delegation") if $ok;
    return $ok;
}

sub check_glue_coherence {
    my ($ctx) = @_;

    my $glue_map = $ctx->{parent_delegation}->{glue_map} || {};
    my $ok = 1;

    if (!%$glue_map) {
        color_line($ctx, 'green', "No glue entries in parent delegation");
        return $ok;
    }

    for my $host (sort keys %$glue_map) {
        my %glue_set   = map { $_ => 1 } @{$glue_map->{$host} // []};
        my %actual_set = (
            map({ $_->address => 1 } @{$ctx->{current}->{data}->{glue}->{$host}->{A}->{rrs} // []} ),
            map({ $_->address => 1 } @{$ctx->{current}->{data}->{glue}->{$host}->{AAAA}->{rrs} // []} ),
        );
        my $lok = 1;
   
        # Trouver les IPs manquantes (dans parent mais pas dans enfant)
        for my $ip (sort keys %glue_set) {
            $lok = 0 if warn_error($ctx, !$actual_set{$ip}  , "Glue for %s: missing IP from zone %s", $host, $ip);
        }

        # Trouver les IPs de trop (dans enfant mais pas dans parent)
        for my $ip (sort keys %actual_set) {
            $lok = 0 if warn_error($ctx,  !$glue_set{$ip}, "Glue for %s: extra IP in zone %s", $host, $ip);
        }

        debug($ctx, "Glue for %s consistent with parent delegation", $host) if $lok;
        
        $ok = 0 unless $lok;
    }

    color_line($ctx, 'green', "All glue entries consistent with parent delegation") if $ok;
    return $ok;
}

# Helpers

sub check_dnskey_cds_cdnskey_consistency_across_ns {
    my ($ctx) = @_;
    my $collection = $ctx->{ns_keytag_collection} // {};

    # Check each type separately: cds, cdnskey, dnskey
    for my $type (qw(cds cdnskey dnskey)) {
        my $all_ok = 1;

        # For each NS, check it has all composite_keys of this type
        for my $ns_name (sort keys %{ $collection->{by_ns} // {} }) {
            for my $composite_key (keys %{ $collection->{$type} // {} }) {
                my $keytag = $collection->{$type}->{$composite_key}->{keytag};
                $all_ok = 0 if warn_error($ctx, !$collection->{by_ns}->{$ns_name}->{$composite_key}->{$type}, 
                    "%s keytag set mismatch on %s: missing %d", uc($type), $ns_name, $keytag);
            }
        }

        # If all NS are consistent, print success
        if ($all_ok) {
            my @all_keytags = sort { $a <=> $b }
                map { $collection->{$type}->{$_}->{keytag} }
                keys %{ $collection->{$type} // {} };
            my $keytags_str = join(', ', @all_keytags) || '(empty)';
            color_line($ctx, 'green', "%s keytag set consistent across all NS: %s", 
                uc($type), $keytags_str);
        } else {
            bbprint($ctx, ""); # Saute une ligne en cas d'errreur
        }
    }
}

1;
