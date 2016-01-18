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
use Test::Simple tests => 81;

# Protocol version 1 
my $k1 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "1024 65537 167844116856772115643578165728646832238977011226514542147340716952508093585575456382466917264655551996680365035622281503365888943953690244682249450439760860544322107624193057364972557417929833165604293403606026919903687463292811771750729180768776277916268938968997228428980058794608820423445889709946628253763 rsa1\n");

ok($k1->{type} eq "rsa", "type should be 'rsa', is '$k1->{type}'");
ok($k1->{protocol} == 1, "protocol should be 1, is $k1->{protocol}");
ok($k1->{name} eq "rsa1", "name should be 'rsa1', is '$k1->{name}'");
ok($k1->{bits} == 1024, "bits should be 1024, is $k1->{bits}");
ok($k1->{strength} == 80, "strength should be 80, is $k1->{strength}");
ok($k1->get_id() eq '91cff00e21764aff1d19933bc7a40056', "id should be 91cff00e21764aff1d19933bc7a40056, is ".$k1->get_id());
my @k1 = Greenend::SSH::Key::get_by_name('rsa1');
ok(@k1 == 1);
ok($k1[0] == $k1);

# Protocol version 2: RSA
my $k2 = Greenend::SSH::Key->new
    ('origin' => 'this',
     'authorized_keys_line'
     => 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQDc7qFIWeamHY4JgU/jfW9gzQpvE0iWnQApCcN2R+jr30XdAVDpyMyuL+YeAvikk23XlqYetBZIlIbUuXtbHzOJbjy5GQ/QxydkGbop6bvGcuChGQh96cJIl4M7Dev2fqP7LCaZlYV1h8aZrwNZHgjzs7JlLnu0qcUT5bkaVsrSKdX2VhwffVFadkK9TjbogJRvabrA1LlAELEOpzwy7BwcHejesARrmJWWqS8uwHjBmbgwIKCQQo7qI77SJ+FGMBJ+wQch7rC1gC1XZH+PMS6cKeEbsSJAC78dKiDuLTmKyN6k1SxflYPJjdyYCZ3Jiurb7iTqyILxDloUHYiGeeq3 rsa2048');
ok($k2->{type} eq "rsa", "type should be 'rsa', is '$k2->{type}'");
ok($k2->{protocol} == 2, "protocol should be 2, is $k2->{protocol}");
ok($k2->{name} eq "rsa2048", "name should be 'rsa2048', is '$k2->{name}'");
ok($k2->{bits} == 2048, "bits should be 2048, is $k2->{bits}");
ok($k2->{strength} == 112, "strength should be 112, is $k2->{strength}");
ok($k2->get_id() eq 'd3d0c0b84efe325d0354d3c36000a198', "id should be d3d0c0b84efe325d0354d3c36000a198, is ".$k2->get_id());

# Same key expressed in protocol 1 syntax
my $k2a = Greenend::SSH::Key->new
    ('origin' => 'that',
     'authorized_keys_line'
     => "2048 65537 27890099936309844001169849360014919587785712948701108795600711012521167629947138715124967965832414993083013177155935677352803260435638299910717276195397800537688069089306001700120819707013775055107662363925784352092326903153096467127388137908943787839948010211262682475843805358385665255996716697074389549381249367625423783798131801920913928720141962092132140798102688322026705708167025658768367583144931055763628772600136988520483666219273294017053976029821219351864288798378909423354426708285506263498515769784601981189756629018210359483677940073118021053548827498248017750198293137422960214220529996023833395063479 whatever");
ok($k2a->get_id() eq 'd3d0c0b84efe325d0354d3c36000a198', "id should be d3d0c0b84efe325d0354d3c36000a198, is ".$k2a->get_id());
ok($k2 == $k2a);
ok($k2->{protocol} == 1, "protocol should be 1, is $k2->{protocol}");
my @k2names = $k2->get_names();
ok(@k2names == 2);
ok($k2names[0] eq 'rsa2048');
ok($k2names[1] eq 'whatever');

# Protocol version 2: DSA
my $k3 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ssh-dss AAAAB3NzaC1kc3MAAACBAPV/+T4AEj/azMpiJnV4rryiE8zcW5qgbgeBHXuhYNEMCoI9DSvBZ7Wbk2zoMgdgRvRp2EE3CWW0xsFcHkPSnX8Ph6nTII3qmrp+nsNvaX/wfMSSrEi/AO8BFMDSjrLPaNewJ6GEUlA5XsEf87OJTRsmrEU7+xJTmttgk6pXDKEFAAAAFQDQDJRseaykcytWouSY1tVY9f7+uQAAAIB5kaRrQMFi3v9ODL2kJa/vCa5t3KB3ELAPSdeHNQJ+kD4imUaEfuAHc6oukesdUL2Ux7pzfnqeGMP9fo/gP67L121JNksaYj+rf6pOHW6/QCrQUuCyNlZlZ9qkw3HowUuc/qGA2D59lUEFleVgcYe9ChTgmTwyMgGQC9tVBebsIQAAAIEAg6PkCpwC/v9uC2DXj9uu2dazAd90o0ycqxNw6ttZldvxp4LLn4cksMluaIJv1kifqNZcwjib61nVZxN/Gq+CNeB1LoKPy0jtNQvFj9jtrK3n9+syv1KpiukrU0Jd2uGQLfA5e4aQFmN+NMCtyuQ3HHCQzf7cWde6t6c0WTe0lpw= dsa1024");
ok($k3->{type} eq "dsa", "type should be 'dsa', is '$k3->{type}'");
ok($k3->{protocol} == 2, "protocol should be 2, is $k3->{protocol}");
ok($k3->{name} eq "dsa1024", "name should be 'dsa1024', is '$k3->{name}'");
ok($k3->{bits} == 1024, "bits should be 1024, is $k3->{bits}");
ok($k3->{strength} == 80, "strength should be 80, is $k3->{strength}");
ok($k3->get_id() eq 'd349bc5c3dc4b13baa59b5777407084b', "id should be d349bc5c3dc4b13baa59b5777407084b, is ".$k3->get_id());

# Protocol version 2: ECDSA
my $k4 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBGovIc1tTB7SWx7ZRLDL3CKglV2jACOCyW0ZTZI/8g0fZNM2Xhx4I4YtJPaY25rHeFpq3aABQR8V6QG3zPBao0g= ecdsa256");
ok($k4->{type} eq "ecdsa", "type should be 'ecdsa', is '$k4->{type}'");
ok($k4->{protocol} == 2, "protocol should be 2, is $k4->{protocol}");
ok($k4->{name} eq "ecdsa256", "name should be 'ecdsa256', is '$k4->{name}'");
ok($k4->{bits} == 256, "bits should be 256, is $k4->{bits}");
ok($k4->{strength} == 128, "strength should be 128, is $k4->{strength}");
ok($k4->get_id() eq '377530fa5462e3e167bc8fc57b2eaca3', "id should be 377530fa5462e3e167bc8fc57b2eaca3, is ".$k4->get_id());

# Protocol version 2: ED25519
my $k5 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDjyq41f8d/RFLFAhpBo5b4BB3qVmaEf4x4FwrdrSM9 ed25519");
ok($k5->{type} eq "ed25519", "type should be 'ed25519', is '$k5->{type}'");
ok($k5->{protocol} == 2, "protocol should be 2, is $k5->{protocol}");
ok($k5->{name} eq "ed25519", "name should be 'ed25519', is '$k5->{name}'");
ok($k5->{bits} == 256, "bits should be 256, is $k5->{bits}");
ok($k5->{strength} == 128, "strength should be 128, is $k5->{strength}");
ok($k5->get_id() eq '279226df0980a1acfe27683d317f7445', "id should be 279226df0980a1acfe27683d317f7445, is ".$k5->get_id());

# Duplicate one of the keys under a clashing name
Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKDjyq41f8d/RFLFAhpBo5b4BB3qVmaEf4x4FwrdrSM9 rsa2048");
my @ks = Greenend::SSH::Key::get_by_name('rsa2048');
ok(@ks == 2);
ok($ks[0] == $k5);
ok($ks[1] == $k2);

my $k6 = Greenend::SSH::Key->new
    ('keyblob'
     => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFDwq3KcbDeOMlbjD/A9jIaDwLtnDRqFlvP6Ra+VwUPx");
ok($k6->get_id() eq '8854af93ce830639110028406dfdc428');
ok($k6->{name} eq '8854af93ce830639110028406dfdc428');

my @keys = Greenend::SSH::Key::all_keys();
#print STDERR "\n", map($_->get_id()."\n", @keys);
ok(@keys == 6);
ok($keys[0] == $k5);
ok($keys[1] == $k4);
ok($keys[2] == $k6);
ok($keys[3] == $k1);
ok($keys[4] == $k3);
ok($keys[5] == $k2);

my @critique = Greenend::SSH::Key::critique(strength => 112);
#print STDERR "\n", map("$_\n", @critique), "----\n";
my @expect = ('Trouble with key 279226df0980a1acfe27683d317f7445',
              '  Key has multiple names',
              '  Names:',
              '    ed25519',
              '    rsa2048',
              'Trouble with key 91cff00e21764aff1d19933bc7a40056',
              '  Key is usable with protocol 1',
              '  rsa 1024 key is too weak',
              '  Names:',
              '    rsa1',
              'Trouble with key d349bc5c3dc4b13baa59b5777407084b',
              '  dsa 1024 key is too weak',
              '  Names:',
              '    dsa1024',
              'Trouble with key d3d0c0b84efe325d0354d3c36000a198',
              '  Key has multiple names',
              '  Key is usable with protocol 1',
              '  Names:',
              '    rsa2048',
              '    whatever',
              '  Origins:',
              '    that',
              '    this',
              'Trouble with name rsa2048:',
              '  Name maps to 2 different keys:',
              '  Key ID 279226df0980a1acfe27683d317f7445',
              '  Key ID d3d0c0b84efe325d0354d3c36000a198',
              '  Origins:',
              '    that',
              '    this');

ok(@critique == scalar @expect);
for my $n (0..$#expect) {
    ok($critique[$n] eq $expect[$n]);
}

