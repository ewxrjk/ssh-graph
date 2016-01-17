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
use Test::Simple tests => 7;

# Protocol version 1
my $k1 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "from=\"kakajou.wlan.anjou.terraraq.org.uk\",no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty,command=\"/usr/lib/openssh/sftp-server\" ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEApaGDo+rQGwbbnPneV1Lo8POUuxhMaWmbAjNNZp0uMgc8nKZlDuvzhr2o/bFk5RLtZLj5ysZRA9zqdkxM1nAcA+0X41qClFYKGIIPihjcvGlfQRW6AxlGe8orwegmxfh7HtDGyLuIg4GcSE4+nTVTT8r7IVP1JIHg+XOXCvtmlIOjGlj7H66PVxPsxsXFPLupcQ5m2KulsxD7JX/oxEe9A4jgoZomLsJoF/4fnTvNQiWM6mTPMcTpHOj9Je5aMieEujZqlXa5wuNG0eylLCvsfgJyHSbMrFEZZMKCenpav07FNdC7qfG5yiMYLMwOemw46iW8g7/avWQYSJMoSbLxFQ== root\@kakajou.wlan.anjou.terraraq.org.uk\n");

ok($k1->{type} eq "rsa", "type should be 'rsa', is '$k1->{type}'");
ok($k1->{protocol} == 2, "protocol should be 2, is $k1->{protocol}");
ok($k1->{name} eq "root\@kakajou.wlan.anjou.terraraq.org.uk", "name should be 'root\@kakajou.wlan.anjou.terraraq.org.uk', is '$k1->{name}'");
ok($k1->{bits} == 2048, "bits should be 2048, is $k1->{bits}");
ok($k1->{strength} == 112, "strength should be 112, is $k1->{strength}");
my @k1 = Greenend::SSH::Key::get_by_name("root\@kakajou.wlan.anjou.terraraq.org.uk");
ok(@k1 == 1);
ok($k1[0] == $k1);
