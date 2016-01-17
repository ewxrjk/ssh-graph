#! /usr/bin/perl -w
#
# Copyright © 2016 Richard Kettlewell
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

use warnings;
use strict;
use Greenend::SSH::Key;
use Test::Simple tests => 10;
use File::Temp qw(tempfile);

my ($fh,$name) = tempfile();
$fh->print("ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDRnGuyArwoBMC/C0CFlaWu2XAua8UK45+dkVRCaM2CHQ4e/w/7XkjQafSCMTETVbfPTG3TEzLkHz4m8luQHhdHx6lW4B34Rbe1Q0nLxCF19dj4oEElN9NvKmmH3zrKCphr7vrKl+sZfV7p0zFq1C7gKC1MW3xeqd5eVrX2lMg2gVIoJGrxHfN144CvAbORYL2VQThOsO7XNJl60q9hskba9wLAZ+kTXxQNLax4Hhm0zkRz4gMExq9uS4KlK4sT+b1eg175fcnK5fm3XI3GdGCjfKYX/irlmpBHiKPWYSU16GPoTmEdUAU6TGNyuloer8okeOdoRnQLeU2yKb7E5IkV richard\@araminta\n");
$fh->flush();

my $k1 = Greenend::SSH::Key->new
    ('pub_key_file' => $name);

ok($k1->{type} eq "rsa", "type should be 'rsa', is '$k1->{type}'");
ok($k1->{protocol} == 2, "protocol should be 2, is $k1->{protocol}");
ok($k1->{name} eq "richard\@araminta", "name should be 'richard\@araminta', is '$k1->{name}'");
ok($k1->{bits} == 2048, "bits should be 2048, is $k1->{bits}");
ok($k1->{strength} == 112, "strength should be 112, is $k1->{strength}");
ok($k1->get_id() eq '9def3c1a3aeb3737ba1c49ab1944df7a');
my @k1 = Greenend::SSH::Key::get_by_name("richard\@araminta");
ok(@k1 == 1);
ok($k1[0] == $k1);
my @ko = $k1->get_origins();
ok(@ko == 1);
ok($ko[0] eq $name);

