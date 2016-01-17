# Copyright © 2013-2016 Richard Kettlewell
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

package Greenend::SSH::Key;
use warnings;
use strict;
use IO::File;
use MIME::Base64;
use Digest;
use Math::BigInt;

=head1 NAME

Greenend::SSH::Key - Information about an SSH public key

=head1 SYNOPSIS

B<use Greenend::SSH::Key;>

=head1 DESCRIPTION

B<Key> objects represent information about SSH public keys.

=cut

# Map IDs to key structures
our %_keys = ();

# Map name to dict of IDs
our %_keys_by_name = ();

# Hash for key fingerprints (anything acceptable to Digest.pm will do)
our $fingerprint_hash = "MD5";

=head1 CONSTRUCTOR

  $key = Greenend::SSH::Key->new(pub_key_file => PATH);

Creates a key object either from a B<.pub> file.

  $key = Greenend::SSH::Key->new(origin => FILENAME,
                                 authorized_keys_line => LINE);

Creates a key object from a line found in an B<authorized_keys> file.

  $key = Greenend::SSH::Key->new(origin => FILENAME,
                                 keyblob => DATA,
                                 name => NAME);

Creates a key object from raw data.  B<DATA> must consist of the key
name followed by the base64 key data.  B<NAME> is optional; if no name
is supplied then the key fingerprint is used.

As well as recording the value of the key this also records the name
of the key and, optionally, the origin.

If the same key (as identified by the hashed of the public key
material) is constructed multiple times you will always get the same
object.  However, the multiple possible names and origins for the key
are tracked.

=cut

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
    $self->{issues} = {};
    $self->{revoked} = 0;
    while(@_ > 0) {
        my $key = shift;
        my $value = shift;
        if($key eq 'pub_key_file') {
            $self->{origin} = $value unless exists $self->{origin};
            $self->_read_pub_key_file($value);
        } elsif($key eq 'authorized_keys_line') {
            $self->_authorized_keys_line($value);
        } elsif($key eq 'keyblob') {
            $self->_keyblob($value);
        } elsif($key eq 'name') {
            $self->{name} = $value;
        } elsif($key eq 'origin') {
            $self->{origin} = $value;
        } else {
            die "$self->{origin}: Greenend::SSH::Key::initialize: unrecognized initialization key '$key'";
        }
    }
    die "$self->{origin}: Greenend::SSH::Key::initialize: keydata not set"
        unless exists $self->{keydata};
    $self->{name} = $self->get_id() unless exists $self->{name};
    $_keys_by_name{$self->{name}}->{$self->get_id()} = 1;
    my $existing;
    if(exists $_keys{$self->get_id()}) {
        $existing = $_keys{$self->get_id()};
        if($self->{protocol} < $existing->{protocol}) {
            $existing->{protocol} = $self->{protocol};
        }
    } else {
        $existing = $self;
        $_keys{$self->get_id()} = $self;
    }
    $existing->{origins}->{$self->{origin}} = 1
        if defined $self->{origin};
    $existing->{names}->{$self->{name}} = 1;
    return $existing;
}

=head1 INSTANCE METHODS

=head2 get_id

  $id = $key->get_id();

Returns the fingerprint of B<$key> in hex.

This fingerprint is constructed as OpenSSH does for protocol 2 keys
(at least up to version 6.7), i.e. as the MD5 hash of the key blob.
So in most cases the hashes will be directly comparable with the ones
OpenSSH shows you.  However, they may differ for protocol 1 keys.

The hash function used may be changed by setting
B<$Greenend::SSH::Key::fingerprint_hash>.  Any value acceptable to
L<Digest> will do.  You must do this before constructing any keys!

=cut

sub get_id($) {
    my $self = shift;
    die "Greenend::SSH::Key::get_id: key not initialized"
        unless exists $self->{keydata};
    # OpenSSH fingerprint format for protocol 2
    my $d = Digest->new($fingerprint_hash);
    $d->add(decode_base64($self->{keydata}));
    return $d->hexdigest();
}

=head2 get_origins

  @origins = $key->get_origins();

Returns a list of origins for B<$key>, as specified to the constructor.

=cut

sub get_origins {
    my $self = shift;
    return sort keys %{$self->{origins}};
}

=head2 get_names

  @names = $key->get_names();

Returns a list of names for B<$key>.

=cut

sub get_names {
    my $self = shift;
    return sort keys %{$self->{names}};
}

=head2 get_accepting_users

  @users = $key->get_accepting_users();

Returns a list of users that accept connections authenticated by
B<$key>.  Each element is a L<Greenend::SSH::User> object.

=cut

sub get_accepting_users {
    my $self = shift;
    return _users(keys %{$self->{accepted_by}});
}

=head2 get_knowing_users

  @users = $key->get_knowing_users();

Returns a list of users that know the private key corresponding to
B<$key>.  Each element is a L<Greenend::SSH::User> object.

=cut

sub get_knowing_users {
    my $self = shift;
    return _users(keys %{$self->{known_by}});
}

=head2 revoke

  $key->revoke()

Marks a key as revoked.

=cut

sub revoke {
    my $self = shift;
    $self->{revoked} = 1;
    return $self;
}

=head2 revoked

  $revoked = $key->revoked();

Returns nonzero if the key is revoked.

=cut

sub revoked {
    my $self = shift;
    return $self->{revoked};
}

=head2 get_trouble

  @trouble = $key->get_trouble(strength => STRENGTH);

Returns a list of problems with this key.

If the optional B<strength> parameter is supplied this is the minimum
permissible security strength, in bits.  The default is 128.  (Note
that asymmetric algorithms - RSA and *DSA - have a much lower strength
than the total number of bits in the key.)

The return value is an English-language description of the problems.
Each list element is a single line with no newline appended.

=cut

sub get_trouble {
    my $key = shift;
    my %args = @_;
    $args{strength} = 128 unless exists $args{strength};
    my @names = $key->get_names();
    my @known_by = $key->get_knowing_users();
    my @trouble = ();
    if(@names > 1) {
        push(@trouble, "Key has multiple names");
        $key->{issues}->{multiple_names} = [@names];
    }
    if($key->{protocol} < 2) {
        push(@trouble, "Key is usable with protocol 1");
        $key->{issues}->{bad_protocol} = 1;
    }
    if(@known_by > 1) {
        push(@trouble,
             "Key ".$key->get_id()." is known by multiple users:",
             map("  $_->{name}", @known_by));
        $key->{issues}->{multiple_users} = [@known_by];
    }
    if($key->{strength} < $args{strength}) {
        push(@trouble, "$key->{type} $key->{bits} key is too weak");
        $key->{issues}->{weak} = $key->{strength};
    }
    return @trouble;
}

########################################################################

=head1 CLASS METHODS

=head2 get_by_id

  $key = Greenend::SSH::Key::get_by_id($id);

Return the key with fingerprint B<$id> (see above), or B<undef> if
there is no such key.

=cut

sub get_by_id($) {
    my $id = shift;
    return $_keys{$id};
}

=head2 get_by_name

  @keys = Greenend::SSH::Key::get_byname($name);

Return the keys with name B<$name>.

=cut

sub get_by_name($) {
    my $name = shift;
    return map(get_by_id($_), sort keys %{$_keys_by_name{$name}});
}

=head2 all_keys

  @keys = Greenend::SSH::Key::all_keys();

Return a list of all keys.

=cut

sub all_keys {
    return map($_keys{$_}, sort keys %_keys);
}

=head2 critique

  @problems = Greenend::SSH::Key::critique(strength => STRENGTH,
                                           select => SUB);

Identify problems found with keys.

If the optional B<strength> parameter is supplied this is the minimum
permissible security strength, in bits.  The default is 128.  (Note
that asymmetric algorithms - RSA and *DSA - have a much lower strength
than the total number of bits in the key.)

The the optional B<select> parameter is supplied, then this is called
for each key to determine if it should be critiqued.  It should return
1 to critique the key and 0 to suppress it.

The return value is an English-language description of the problems.
Each list element is a single line with no newline appended.

As well as computing this list, the issues with each key are recorded.
(This is not affected by the B<select> parameter.)
See below for discussion.

=cut

# Critique the set of all keys
sub critique {
    my %args = @_;
    $args{strength} = 128 unless exists $args{strength};
    $args{select} = sub { return 1; } unless exists $args{select};
    my @c = ();
    for my $key (all_keys()) {
        my @trouble = $key->get_trouble(%args);
        my @names = $key->get_names();
        my @origins = $key->get_origins();
        if(@trouble && &{$args{select}}($key)) {
            push(@c, "Trouble with key ".$key->get_id());
            push(@c, map("  $_", @trouble));
            push(@c, "  Names:",
                 map("    $_", @names));
            if(@origins > 0) {
                push(@c,
                     "  Origins:",
                     map("    $_", @origins));
            }
        }
    }
    for my $name (sort keys %_keys_by_name) {
        my @keys = grep &{$args{select}}($_),get_by_name($name);
        if(@keys > 1) {
            push(@c,
                 "Trouble with name $name:",
                 "  Name maps to ".(scalar @keys)." different keys:");
            for my $key (@keys) {
                $key->{issues}->{clashing_name} = [@keys];
                my @origins = $key->get_origins();
                push(@c,
                     "  Key ID ".$key->get_id());
                if(@origins > 0) {
                    push(@c,
                         "  Origins:",
                         map("    $_", @origins));
                }
            }
        }
    }
    return @c;
}

=head1 INSTANCE VARIABLES

=head2 issues

This is updated by the B<critique> method and the corresponding method
L<Greenend::SSH::User/critique>.  It is a hash ref, and the keys have
the following meanings:

=head3 multiple_names

  $key->{issues}->{multiple_names} = [$name0, $name1, ...];

If the key has multiple names, they are listed here.

=head3 bad_protocol

  $key->{issues}->{bad_protocol} = $protocol;

If the key is usable with SSH protocol 1, this is set to 1.

=head3 multiple_users

  $key->{issues}->{multiple_users} = [$user0, $user1, ...]

If the key is known to multiple users, they are listed here.  Each
element is a L<Greenend::SSH::User> object.

=head3 strength

  $key->{issues}->{strength} = $bits;

If the key is too weak, its strength is listed here.

=head3 clashing_name

  $key->{issues}->{clashing_name} = [$key0, $key1, ...]

If this key shares a name with any other key, all such keys are listed
here.

=head3 multiple_paths

  $key->{issues}->{multiple_paths}->{$username} = 1

If B<$username> accepts connections authenticated both by B<$key> and
also by some other key whose private half is known to the same user as
knows the private half of B<$key>, then this is set.

Note that this is only set by L<Greenend::SSH::User/critique>.

=cut

########################################################################

# Read a OpenSSH *.pub file
sub _read_pub_key_file($$) {
    my $self = shift;
    my $path = shift;
    my $f = IO::File->new($path, "r");
    die "ERROR: $path: $!\n" unless $f;
    my $line = <$f>;
    $f->close();
    chomp $line;
    if(!$self->_public_key_text($line)) {
        die "ERROR: cannot parse key: $line\n";
    }
    return $self;
}

# Read one line in an OpenSSH authorized_keys file
sub _authorized_keys_line($$) {
    my $self = shift;
    local $_ = shift;
    chomp $_;

    # Docs say options field never starts with a number, but non-options often
    # start with a non-number, so this seems to be pretty useless.  Instead we
    # just try to match plausible and well-known option names.
    #
    # TODO 'cert-authority' and 'principals' deserve special treatment,
    # as they expand the set of keys that will actually be accepted.
    while(s/^((cert-authority|no-[0-9a-z\-]+)|([a-z]+=\"([^\"\\]|\\[\"\\])*\")),*//gi) {
    }
    s/^\s+//;

    if(!$self->_public_key_text($_)) {
        die "ERROR: cannot parse key: $_\n";
    }
    return $self;
}

sub _public_key_text($$) {
    my $self = shift;
    local $_ = shift;
    if(/^\s*(\d+)\s+([0-9a-f]+)\s+([0-9a-f]+)\s+(.*)$/i) {
        # 1: bits exponent modulus comment
        $self->{type} = "rsa";
        my $n = (new Math::BigInt($3))->as_hex();
        my $e = (new Math::BigInt($2))->as_hex();
        $self->{protocol} = 1;
        $self->{name} = $4;
        $self->{bits} = $1;
        $self->{keydata} = encode_base64(pack("l>/a l>/a l>/a",
                                              "ssh-rsa",
                                              _hex_to_mpint($e),
                                              _hex_to_mpint($n)));
    } elsif(/^\s*([a-z0-9\-]+)\s+([0-9a-z\+\/=]+)\s+(.*)$/i) {
        # 2: type keydata comment
        $self->{type} = $1;
        $self->{keydata} = $2;
        $self->{protocol} = 2;
        $self->{name} = $3;
    } else {
        return 0;
    }
    $self->_set_strength();
    return 1;
}

sub _keyblob($$) {
    my $self = shift;
    local $_ = shift;
    if(/^\s*([a-z0-9\-]+)\s+([0-9a-z\+\/=]+)(\s+(.*))?$/i) {
        $self->{type} = $1;
        $self->{keydata} = $2;
        $self->{protocol} = 2;
        $self->{name} = $4 if defined $4;
    } else {
        return 0;
    }
    $self->_set_strength();
    return 1;
}

# Set the strength of a key
sub _set_strength($) {
    # http://csrc.nist.gov/publications/nistpubs/800-57/sp800-57_part1_rev3_general.pdf
    my $self = shift;
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
        $self->{strength} = _nfs_strength($self->{bits});
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
        my $lstrength = _nfs_strength($lbits);
        my $nstrength = _discrete_log_strength($nbits);
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
            $self->{strength} = 80;
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

sub _users {
    return map($Greenend::SSH::User::_users{$_}, @_);
}

# Returns the strength for a prime (DSA) or product (RSA) satisfying
# 2^($bits-1)<p<2^$bits
sub _nfs_strength($) {
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
sub _discrete_log_strength($) {
    my $bits = shift;
    return int($bits/2);
}

sub _hex_to_mpint($) {
    local $_ = shift;
    s/^(0x)?0*//i;
    $_ = "00$_" if /^[90a-f]/i;
    return pack("H*", $_);
}

return 1;

=head1 NOTES

A future version of this API may hide the B<issues> member behind a
getter method.  Be prepared to write users.

=head1 SEE ALSO

L<Greenend::SSH::User>, L<ssh-graph(1)>
