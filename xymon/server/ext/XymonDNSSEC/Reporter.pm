package XymonDNSSEC::Reporter;

use strict;
use warnings;
use Data::Dumper;
use Exporter qw(import);

our @EXPORT_OK = qw(
    color_line
    color_print
    bbprint
    debug
    check_error
    warn_error
    redwarn_error
    human_duration
);
our %EXPORT_TAGS = (
    all => \@EXPORT_OK,
);

sub debug {
    my ($ctx, $fmt, @args) = @_;
    return unless $ctx && ref $ctx eq 'HASH' && $ctx->{debug};
    bbprint(@_);
}

sub bbprint {
    my ($ctx, $fmt, @args) = @_;
    my $bb = $ctx->{bb};
    return unless $bb;
    $bb->sprintf($fmt . "\n", @args);
}

sub _signal_error {
    my ($ctx, $color, $err, $fmt, @args) = @_;
    return $err unless $err;
    color_line($ctx, $color, $fmt, @args);
    return $err;
}

sub check_error { _signal_error($_[0], 'red',    @_[1..$#_]) }
sub warn_error  { _signal_error($_[0], 'yellow', @_[1..$#_]) }

sub redwarn_error {
    my ($ctx, $err, $fmt, @args) = @_;
    return $err unless $err;
    color_print($ctx, "yellow", "red", $fmt, @args);
    return $err;
}

sub color_print {
    my ($ctx, $color_status, $color_message, $fmt, @args) = @_;
    return unless $ctx && ref $ctx eq 'HASH';
    my $bb = $ctx->{bb};
    return unless $bb;
    $bb->color_print($color_status, sprintf("&$color_message $fmt\n", @args));
    return;
}

sub color_line {
    my ($ctx, $color, $fmt, @args) = @_;
    return unless $ctx && ref $ctx eq 'HASH';
    my $bb = $ctx->{bb};
    return unless $bb;
    $bb->color_line($color, sprintf($fmt . "\n", @args));
    return;
}

sub human_duration {
    my ($seconds, $with_subseconds) = @_;
    return '0s' unless defined $seconds && $seconds > 0;

    my $fractional = $seconds - int($seconds);
    my $days    = int($seconds / 86400);
    my $rem_s   = $seconds % 86400;
    my $hours   = int($rem_s / 3600);
    $rem_s      = $rem_s % 3600;
    my $minutes = int($rem_s / 60);
    my $secs    = int($rem_s % 60) + $fractional;

    if ($days > 0) {
        return sprintf('%dd%02dh', $days, $hours);
    } elsif ($hours > 0) {
        return sprintf('%dh%02dm', $hours, $minutes);
    } elsif ($minutes > 0) {
        return sprintf('%dm%02ds', $minutes, $secs);
    }
    if (defined $with_subseconds && $fractional > 0) {
        if ($secs <= 1) {
            my $ms = int(($secs * 1000) + 0.5);
            return sprintf('%dms', $ms);
        }
        return sprintf('%.3fs', $seconds);
    }

    return sprintf('%ds', $secs);
}


1;
