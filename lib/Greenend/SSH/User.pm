package Greenend::SSH::User;
use Greenend::SSH::Key;
use warnings;
use strict;

our %_users = ();
our $_next_serial = 0;

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
    die "Greenend::SSH::Key::get_id: key not initialized"
        unless exists $self->{name};
    if(exists $_users{$self->{name}}) {
        return $_users{$self->{name}};
    }
    $_users{$self->{name}} = $self;
    return $self;
}

sub add_knows_key {
    my $self = shift;
    my $key = shift;
    $self->{known_keys}->{$key->get_id()} = 1;
    $key->{known_by}->{$self->{name}} = 1;
    return $self;
}

sub get_known_keys {
    my $self = shift;
    return _keys(keys %{$self->{known_keys}});
}

sub knows_key {
    my $self = shift;
    my $key = shift;
    return exists $self->{known_keys}->{$key->get_id()};
}

sub add_accepts_key {
    my $self = shift;
    my $key = shift;
    $self->{accepts_keys}->{$key->get_id()} = 1;
    $key->{accepted_by}->{$self->{name}} = 1;
    return $self;
}

sub get_accepted_keys {
    my $self = shift;
    return _keys(keys %{$self->{accepts_keys}});
}

sub accepts_key {
    my $self = shift;
    my $key = shift;
    return exists $self->{accepts_keys}->{$key->get_id()};
}

########################################################################

sub all_users {
    return map($_users{$_}, sort keys %_users);
}

sub critique {
    my %args = @_;
    $args{strength} = 128 unless exists $args{strength};
    my @c = ();
    for my $u (all_users()) {
        my @accepted_keys = $u->get_accepted_keys();
        my %accepted_users = ();
        my @trouble = ();
        for my $k (@accepted_keys) {
            push(@trouble, "  Trusts weak key ".$k->get_id." ($k->{name})")
                if $k->{strength} < $args{strength};
            for my $uu ($k->get_knowing_users()) {
                $accepted_users{$uu->{name}} = 0
                    unless exists $accepted_users{$uu->{name}};
                $accepted_users{$uu->{name}} += 1;
            }
        }
        for my $uuid (keys %accepted_users) {
            if($accepted_users{$uuid} > 1) {
                my $uu = $_users{$uuid};
                push(@trouble, "  User $uu->{name} can access $u->{name} using multiple keys:");
                for my $k (@accepted_keys) {
                    if($uu->knows_key($k)) {
                        push(@trouble, "    ".$k->get_id." ($k->{name})");
                        $k->{issues}->{multiple_paths}->{$u->{name}} = 1;
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
