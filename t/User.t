#! /usr/bin/perl -w
#
# Copyright © 2015, 2016 Richard Kettlewell
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
use Greenend::SSH::User;
use Test::Simple tests => 20;

my $u1 = Greenend::SSH::User->new(name => 'bob');
my $u2 = Greenend::SSH::User->new(name => 'fred');

my $k1 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "1024 65537 167844116856772115643578165728646832238977011226514542147340716952508093585575456382466917264655551996680365035622281503365888943953690244682249450439760860544322107624193057364972557417929833165604293403606026919903687463292811771750729180768776277916268938968997228428980058794608820423445889709946628253763 rsa1\n");
my $k2 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc7qFIWeamHY4JgU/jfW9gzQpvE0iWnQApCcN2R+jr30XdAVDpyMyuL+YeAvikk23XlqYetBZIlIbUuXtbHzOJbjy5GQ/QxydkGbop6bvGcuChGQh96cJIl4M7Dev2fqP7LCaZlYV1h8aZrwNZHgjzs7JlLnu0qcUT5bkaVsrSKdX2VhwffVFadkK9TjbogJRvabrA1LlAELEOpzwy7BwcHejesARrmJWWqS8uwHjBmbgwIKCQQo7qI77SJ+FGMBJ+wQch7rC1gC1XZH+PMS6cKeEbsSJAC78dKiDuLTmKyN6k1SxflYPJjdyYCZ3Jiurb7iTqyILxDloUHYiGeeq3 rsa2048');

ok($u1->{name} eq 'bob');
ok($u2->{name} eq 'fred');

$u1->add_knows_key($k1, []);
$u2->add_knows_key($k1, []);
$u2->add_knows_key($k2, []);
my @u1_known = $u1->get_known_keys();
my @u2_known = $u2->get_known_keys();

ok(@u1_known == 1);
ok($u1_known[0] eq $k1);
ok(@u2_known == 2);
ok($u2_known[0] == $k1);
ok($u2_known[1] == $k2);

$u2->add_accepts_key($k1);
my @u1_accepted = $u1->get_accepted_keys();
my @u2_accepted = $u2->get_accepted_keys();
ok(@u1_accepted == 0);
ok(@u2_accepted == 1);
ok($u2_accepted[0] == $k1);

my @critique = Greenend::SSH::User::critique();
#print STDERR "\n", map("$_\n", @critique), "----\n";
my @expect = ('Trouble with user fred',
              '  Trusts weak key 91cff00e21764aff1d19933bc7a40056 (rsa1)');
ok(@critique == scalar @expect,
   "expect ".(scalar @expect)." got ".(scalar @critique));
for my $n (0..$#expect) {
    ok($critique[$n] eq $expect[$n],
       "expect <$expect[$n]> got <$critique[$n]>");
}

$u2->add_accepts_key($k2);
@critique = Greenend::SSH::User::critique();
#print STDERR "\n", map("$_\n", @critique), "----\n";
@expect =    ('Trouble with user fred',
              '  Trusts weak key 91cff00e21764aff1d19933bc7a40056 (rsa1)',
              '  Trusts weak key d3d0c0b84efe325d0354d3c36000a198 (rsa2048)',
              '  User fred can access fred using multiple keys:',
              '    91cff00e21764aff1d19933bc7a40056 (rsa1)',
              '    d3d0c0b84efe325d0354d3c36000a198 (rsa2048)');

ok(@critique == scalar @expect,
   "expect ".(scalar @expect)." got ".(scalar @critique));
for my $n (0..$#expect) {
    ok($critique[$n] eq $expect[$n],
       "expect <$expect[$n]> got <$critique[$n]>");
}
