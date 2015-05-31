#! /usr/bin/perl -w
#
# Copyright © 2015 Richard Kettlewell
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
     => "1024 37 95633395528117590747303319371338448851686531460586925513248626947974833009238798388199329302111402320576268507724784771246224785673098716306832520795997763067549719287376372175346609804890861650378436221064848327626639950669591963095939342996298572807646637073406245108182135449004573333607292244832714236837 root\@sfere\n");
my $k2 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAw4IKtGiqHBOfPp1VW9ZF8vD6tOa6r46iwR9neok10hbEG4bp+Yljof25dUWJoTXLUkqk4h48h4A+vojkVbvWldw61xwefmTAVW7UKt0kVwHlDNBYxAf1P1KvWaU96XOwtT9s3dG75auWadnN39wDbrVL/ZMr4NSekju0PTq2h9rPJN6X2NLxM7/z82Grkz4FbT3isB4Kyhn+IJ89KepGGJG91s3dUwiC0VpYOqiAwPz9RExwutpdI4rNqoy51swAiQfnIV7fSxekj7Mv/Jbhsbt0khhgAOOj1D+lCHlbatQNBKDorXulv3HwXXfnyWW3Tqg8XirvjJbUw69ApMHYpQ== richard@araminta');

ok($u1->{name} eq 'bob');
ok($u2->{name} eq 'fred');

$u1->add_knows_key($k1);
$u2->add_knows_key($k1);
$u2->add_knows_key($k2);
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
              '  Trusts weak key 04c2aa02e11c78269526f3f67a7c436a (root@sfere)');
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
              '  Trusts weak key 04c2aa02e11c78269526f3f67a7c436a (root@sfere)',
              '  Trusts weak key 35dd6a606baf6692f59e31138898b0f8 (richard@araminta)',
              '  User fred can access fred using multiple keys:',
              '    04c2aa02e11c78269526f3f67a7c436a (root@sfere)',
              '    35dd6a606baf6692f59e31138898b0f8 (richard@araminta)');

ok(@critique == scalar @expect,
   "expect ".(scalar @expect)." got ".(scalar @critique));
for my $n (0..$#expect) {
    ok($critique[$n] eq $expect[$n],
       "expect <$expect[$n]> got <$critique[$n]>");
}
