# Copyright © 2015-2016 Richard Kettlewell
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

package Greenend::SSH::User;
use Greenend::SSH::Key;
use warnings;
use strict;

=head1 NAME

Greenend::SSH::User - Information about a user of SSH

=head1 SYNOPSIS

B<use Greenend::SSH::User;>

=head1 DESCRIPTION

B<User> objects represent information about users of SSH.  They are
meant to be used in conjunction with L<Greenend::SSH::User> objects.

=cut

our %_users = ();
our $_next_serial = 0;

=head1 CONSTRUCTOR

  $user = Greenend::SSH::User->new(name => NAME);

Creates a user object with B<NAME> as its name.

If the same user (as identified by name) is constructed multiple times
you will always get the same object.

=cut

sub new {
    my $self = bless {}, shift;
    return $self->initialize(@_);
}

# OBJECT->initialize(KEY=>VALUE, ...)
sub initialize {
    my $self = shift;
    $self->{known_keys} = {};
    $self->{accepts_keys} = {};
    $self->{serial} = $_next_serial++;
    while(@_ > 0) {
        my $key = shift;
        my $value = shift;
        if($key eq 'name') {
            $self->{name} = $value;
        } else {
            die "Greenend::SSH::User::initialize: unrecognized initialization key '$key'";
        }
    }
    die "Greenend::SSH::User::initialize: user not initialized"
        unless exists $self->{name};
    if(exists $_users{$self->{name}}) {
        return $_users{$self->{name}};
    }
    $_users{$self->{name}} = $self;
    return $self;
}

=head1 INSTANCE METHODS

In this section, B<$key> is always a L<Greenend::SSH::Key> object.

=head2 add_knows_key

  $user->add_knows_key($key);

Record that B<$user> knows the private half of B<$key>.

=cut

sub add_knows_key {
    my $self = shift;
    my $key = shift;
    $self->{known_keys}->{$key->get_id()} = 1;
    $key->{known_by}->{$self->{name}} = 1;
    return $self;
}

=head2 get_known_keys

  @keys = $user->get_known_keys();

Returns the list of keys that B<$user> knows the private half of.
Each element is a L<Greenend::SSH::Key> object.

=cut

sub get_known_keys {
    my $self = shift;
    return _keys(keys %{$self->{known_keys}});
}

=head2 knows_key

  if($user->knows_key($key)) { #...

Returns a true if B<$user> knows the private half of B<$key>.

=cut

sub knows_key {
    my $self = shift;
    my $key = shift;
    return exists $self->{known_keys}->{$key->get_id()};
}

=head2 add_accepts_key

  $user->add_accepts_key($key);

Record that B<$user> accepts connections authenticated by B<$key>.

=cut

sub add_accepts_key {
    my $self = shift;
    my $key = shift;
    $self->{accepts_keys}->{$key->get_id()} = 1;
    $key->{accepted_by}->{$self->{name}} = 1;
    return $self;
}

=head2 get_accepted_keys

  @keys = $user->get_accepted_keys();

Returns the list of keys that B<$user> accepts connections
authenticated by.  Each element is a L<Greenend::SSH::Key> object.

=cut

sub get_accepted_keys {
    my $self = shift;
    return _keys(keys %{$self->{accepts_keys}});
}

=head2 accepts_key

  if($user->accepts_key($key)) { #...

Returns a true if B<$user> accepts connections authenticated by B<$key>.

=cut

sub accepts_key {
    my $self = shift;
    my $key = shift;
    return exists $self->{accepts_keys}->{$key->get_id()};
}

########################################################################

=head1 CLASS METHODS

=head2 all_users

  @users = Greenend::SSH::User::all_users();

Returns a list of all known users.

=cut

sub all_users {
    return map($_users{$_}, sort keys %_users);
}

=head2 critique

  @problems = Greenend::SSH::User::critique();
  @problems = Greenend::SSH::User::critique(strength => STRENGTH);

Identify problems found with users and keys.

If the B<strength> parameter is supplied this is the minimum
permissible security strength, in bits.  The default is 128.  (Note
that asymmetric algorithms - RSA and *DSA - have a much lower strength
than the total number of bits in the key.)

The return value is an English-language description of the problems.
Each list element is a single line with no newline appended.

As well as computing this list, the issues with each key are recorded.
See L<Greenend::SSH::Key/issues> for the details.

=cut

sub critique {
    my %args = @_;
    $args{strength} = 128 unless exists $args{strength};
    my @c = ();
    for my $u (all_users()) {
        my @accepted_keys = $u->get_accepted_keys();
        my %accepted_users = ();
        my @trouble = ();
        for my $key (@accepted_keys) {
            my $id = $key->get_id();
            my $name = $key->{name};
            push(@trouble, "  Trusts weak key $id ($key->{name})")
                if $key->{strength} < $args{strength};
            push(@trouble, "  Trusts revoked key $id ($key->{name})")
                if $key->revoked();
            for my $uu ($key->get_knowing_users()) {
                $accepted_users{$uu->{name}} = 0
                    unless exists $accepted_users{$uu->{name}};
                $accepted_users{$uu->{name}} += 1;
            }
        }
        for my $uuid (keys %accepted_users) {
            if($accepted_users{$uuid} > 1) {
                my $uu = $_users{$uuid};
                push(@trouble, "  User $uu->{name} can access $u->{name} using multiple keys:");
                for my $key (@accepted_keys) {
                    if($uu->knows_key($key)) {
                        push(@trouble, "    ".$key->get_id." ($key->{name})");
                        $key->{issues}->{multiple_paths}->{$u->{name}} = 1;
                    }
                }
            }
        }
        if(@trouble > 0) {
            push(@c, "Trouble with user $u->{name}", @trouble);
        }
    }
    # TODO critique unused keys?
    return @c;
}

########################################################################

sub _keys {
    return map(Greenend::SSH::Key::get_by_id($_), sort @_);
}

1;

=head1 SEE ALSO

L<Greenend::SSH::Key>, L<ssh-graph(1)>
