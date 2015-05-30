package Greenend::SSH::Key;
use warnings;
use strict;
use IO::File;
use MIME::Base64;
use Digest::SHA qw(sha1_hex);
use Math::BigInt;

# Map IDs to key structures
our %keys = ();

# new Greenend::SSH::Key(KEY=>VALUE, ...)
sub new {
    my $self = bless {}, shift;
    return $self->initialize(@_);
}

# OBJECT->initialize(KEY=>VALUE, ...)
sub initialize {
    my $self = shift;
    $self->{known_by} = {};
    $self->{accepted_by} = {};
    $self->{names} = {};
    $self->{origins} = {};
    while(@_ > 0) {
        my $key = shift;
        my $value = shift;
        if($key eq 'pub_key_file') {
            $self->read_pub_key_file($value);
        } elsif($key eq 'authorized_keys_line') {
            $self->authorized_keys_line($value);
        } elsif($key eq 'origin') {
            $self->{origin} = $value;
        } else {
            die "Greenend::SSH::Key::initialize: unrecognized initialization key '$key'";
        }
    }
    return $keys{$self->get_id()};
}

# Read a OpenSSH *.pub file
sub read_pub_key_file($$) {
    my $self = shift;
    my $path = shift;
    my $f = IO::File::new($path, "r");
    die "ERROR: $path: $!\n" unless $f;
    my $line = <$f>;
    $f->close();
    return $self->authorized_keys_line($line);
}

# Read one line in an OpenSSH authorized_keys file
sub authorized_keys_line($$) {
    my $self = shift;
    local $_ = shift;
    chomp $_;
    if(!$self->authorized_keys_fragment($_)
       and /^\s*([^\s\"]|\"([^\"]|\\\")*\")+\s+(.*)/) {
        my $suffix = $3;
        if(!self->authorized_keys_fragment($suffix)) {
            die "ERROR: cannot parse key: $_\n";
        }
    }
    return $self;
}

sub authorized_keys_fragment($$) {
    my $self = shift;
    local $_ = shift;
    if(/^\s*(\d+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(.*)$/i) {
        # 1: bits exponent modulus comment
        $self->{type} = "rsa";
        $self->{keydata} = "$2-$3";
        $self->{n} = (new Math::BigInt($3))->as_hex();
        $self->{e} = (new Math::BigInt($2))->as_hex();
        $self->{protocol} = 1;
        $self->{name} = $4;
        $self->{bits} = $1;
    } elsif(/^\s*([a-z0-9\-]+)\s+([0-9a-z\+\/=]+)\s+(.*)$/i) {
        # 2: type keydata comment
        $self->{type} = $1;
        $self->{keydata} = $2;
        $self->{protocol} = 2;
        $self->{name} = $3;
    } else {
        return 0;
    }
    if($self->{type} eq 'rsa') {
        $self->{n} =~ s/^(0x)?0*//i;
        $self->{e} =~ s/^(0x)?0*//i;
    }
    $self->set_strength();
    my $existing;
    if(exists $keys{$self->get_id()}) {
        $existing = $keys{$self->get_id()};
    } else {
        $existing = $self;
        $keys{$self->get_id()} = $self;
    }
    $existing->{origins}->{$self->{origin}} = 1
        if defined $self->{origin};
    $existing->{names}->{$self->{name}} = 1;
    return 1;
}

# Set the strength of a key
sub set_strength($) {
    # http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf
    my $self = shift;
    if($self->{protocol} == 1) {
        $self->{strength} = prime_strength($self->{bits});
        return;
    }
    my $decoded = decode_base64($self->{keydata});
    # Data type representations:
    #    http://tools.ietf.org/html/rfc4251#section-5
    my $type = unpack("l>/a", $decoded);
    if($type eq 'ssh-rsa') {
        $self->{type} = 'rsa';
        # RSA key format:
        #    http://tools.ietf.org/html/rfc4253#section-6.6
        my ($type, $e, $n) = unpack("l>/a l>/a l>/a", $decoded);
        $n =~ s/^\0*//;
        $self->{bits} = 8 * length($n);
        $self->{n} = unpack("H*", $n);
        $self->{e} = unpack("H*", $e);
        $self->{strength} = prime_strength($self->{bits});
    } elsif($type eq 'ssh-dss') {
        $self->{type} = 'dsa';
        # DSA key format:
        #    http://tools.ietf.org/html/rfc4253#section-6.6
        my ($type, $p, $q, $g, $y) = unpack("l>/a l>/a l>/a l>/a l>/a",
                                            $decoded);
        $p =~ s/^\0*//;
        $q =~ s/^\0*//;
        my $lbits = 8 * length($p);
        my $nbits = 8 * length($q);
        $self->{bits} = $lbits;
        my $lstrength = prime_strength($lbits);
        my $nstrength = discrete_log_strength($nbits);
        $self->{strength} = ($lstrength < $nstrength ? $lstrength
                             : $nstrength);
    } elsif($type =~ /^ecdsa-/) {
        $self->{type} = 'ecdsa';
        my ($type, $domain, $q) = unpack("l>/a l>/a l>/a", $decoded);
        # Key format:
        #    http://tools.ietf.org/html/rfc5656#section-3.1
        # Domain parameter IDs:
        #    http://tools.ietf.org/html/rfc5656#section-10
        # NIST recommended curves:
        #    http://csrc.nist.gov/groups/ST/toolkit/documents/dss/NISTReCur.pdf
        if($domain eq '1.2.840.10045.3.1.1') { # nistp192
            $self->{bits} = 192;
            $self->{strength} = 80;
        } elsif($domain eq '1.3.132.0.33') { # nistp224
            $self->{bits} = 224;
            $self->{strength} = 112;
        } elsif($domain eq 'nistp256') {
            $self->{bits} = 256;
            $self->{strength} = 128;
        } elsif($domain eq 'nistp384') {
            $self->{bits} = 384;
            $self->{strength} = 192;
        } elsif($domain eq 'nistp521') {
            $self->{bits} = 521;
            $self->{strength} = 256;
        } elsif($domain eq '1.3.132.0.1') { # nistk163
            $self->{bits} = 163;
            $self->{strength} = $80;
        } elsif($domain eq '1.3.132.0.26') { # nistb233
            $self->{bits} = 233;
            $self->{strength} = 112;
        } elsif($domain eq '1.3.132.0.16') { # nistk283
            $self->{bits} = 283;
            $self->{strength} = 128;
        } elsif($domain eq '1.3.132.0.36') { # nistk409
            $self->{bits} = 409;
            $self->{strength} = 192;
        } elsif($domain eq '1.3.132.0.37') { # nistb409
            $self->{bits} = 409;
            $self->{strength} = 192;
        } elsif($domain eq '1.3.132.0.38') { # nistt571
            $self->{bits} = 571;
            $self->{strength} = 256;
        } else {
            die "ERROR: unrecognized EC domain parameters $domain\n";
        }
    } elsif($type eq 'ssh-ed25519') {
        # ed25519 keys are always 256 bits long
        $self->{type} = 'ed25519';
        $self->{bits} = 256;
        $self->{strength} = 128;
    } else {
        die "ERROR: unrecognized key type $type\n";
    }
}

# Get the ID of a key
sub get_id($) {
    my $self = shift;
    die "Greenend::SSH::Key::get_id: key not initialized"
        unless exists $self->{keydata};
    if($self->{type} eq 'rsa') {
        # Special-case RSA so that keys used with both protocol 1 and
        # 2 get the same ID.
        return sha1_hex("$self->{n}:$self->{e}");
    } else {
        return sha1_hex($self->{keydata});
    }
}

# Get a list of the places a key was found
sub get_origins {
    my $self = shift;
    return sort keys %{$self->{origin}};
}

# Get a list of the names for this key
sub get_names {
    my $self = shift;
    return sort keys %{$self->{names}};
}

# Returns the strength for a prime field with modulus 2^($bits-1)<p<2^$bits
sub prime_strength($) {
    my $bits = shift;
    if($bits < 1024) {
        return 0;
    } elsif($bits < 2048) {
        return 80;
    } elsif($bits < 3072) {
        return 112;
    } elsif($bits < 7680) {
        return 128;
    } elsif($bits < 15360) {
        return 192;
    } else {
        return 256;
    }
}

# Return the strength of a discrete log group with order 2^($bits-1)<q<2^$bits
sub discrete_log_strength($) {
    my $bits = shift;
    return int($bits/2);
}

# Get a key by ID
sub get_by_id($) {
    my $id = shift;
    return $keys{$id};
}

# Get a list of all keys
sub all_keys {
    return map($keys{$_}, sort keys %keys);
}

return 1;
