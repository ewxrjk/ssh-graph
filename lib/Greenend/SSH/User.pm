package Greenend::SSH::User;
use Greenend::SSH::Key;
use warnings;
use strict;

our $next_id = 0;
our %users = ();

# new Greenend::SSH::User(KEY=>VALUE, ...)
sub new {
    my $self = bless {}, shift;
    return $self->initialize(@_);
}

# OBJECT->initialize(KEY=>VALUE, ...)
sub initialize {
    my $self = shift;
    $self->{known_keys} = {};
    $self->{accepts_keys} = {};
    $self->{id} = ++$next_id;
    $users{$self->{id}} = $self;
    while(@_ > 0) {
        my $key = shift;
        my $value = shift;
        if($key eq 'name') {
            $self->{name} = $value;
        } else {
            die "Greenend::SSH::User::initialize: unrecognized initialization key '$key'";
        }
    }
    die "Greenend::SSH::Key::get_id: key not initialized"
        unless exists $self->{name};
    return $self;
}

sub add_knows_key {
    my $self = shift;
    my $key = shift;
    $self->{known_keys}->{$key->get_id()} = 1;
    $key->{known_by}->{$self->{id}} = 1;
    return $self;
}

sub get_known_keys {
    my $self = shift;
    return _keys(keys %{$self->{known_keys}});
}

sub add_accepts_key {
    my $self = shift;
    my $key = shift;
    $self->{accepts_keys}->{$key->get_id()} = 1;
    $key->{accepted_by}->{$self->{id}} = 1;
    return $self;
}

sub get_accepted_keys {
    my $self = shift;
    return _keys(keys %{$self->{accepts_keys}});
}

sub all_users {
    return map($users{$_}, sort keys %users);
}

sub _keys {
    return map(Greenend::SSH::Key::get_by_id($_), sort @_);
}

1;
