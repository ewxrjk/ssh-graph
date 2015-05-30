use warnings;
use strict;
use Greenend::SSH::Key;
use Test::Simple tests => 40;

# Protocol version 1 
my $k1 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "1024 37 95633395528117590747303319371338448851686531460586925513248626947974833009238798388199329302111402320576268507724784771246224785673098716306832520795997763067549719287376372175346609804890861650378436221064848327626639950669591963095939342996298572807646637073406245108182135449004573333607292244832714236837 root\@sfere\n");

ok($k1->{type} eq "rsa", "type should be 'rsa', is '$k1->{type}'");
ok($k1->{protocol} == 1, "protocol should be 1, is $k1->{protocol}");
ok($k1->{name} eq "root\@sfere", "type should be 'root\@sfere', is '$k1->{name}'");
ok($k1->{bits} == 1024, "bits should be 1024, is $k1->{bits}");
ok($k1->{strength} == 80, "strength should be 80, is $k1->{strength}");
ok($k1->{e} eq '25', "public exponent should be (hex) 25, is $k1->{e}");
ok($k1->get_id() eq 'c3022b3cc12cae1616504a629794ac4c6aad7d38', "id should be c3022b3cc12cae1616504a629794ac4c6aad7d38, is ".$k1->get_id());

# Protocol version 2: RSA
my $k2 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => 'ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEAw4IKtGiqHBOfPp1VW9ZF8vD6tOa6r46iwR9neok10hbEG4bp+Yljof25dUWJoTXLUkqk4h48h4A+vojkVbvWldw61xwefmTAVW7UKt0kVwHlDNBYxAf1P1KvWaU96XOwtT9s3dG75auWadnN39wDbrVL/ZMr4NSekju0PTq2h9rPJN6X2NLxM7/z82Grkz4FbT3isB4Kyhn+IJ89KepGGJG91s3dUwiC0VpYOqiAwPz9RExwutpdI4rNqoy51swAiQfnIV7fSxekj7Mv/Jbhsbt0khhgAOOj1D+lCHlbatQNBKDorXulv3HwXXfnyWW3Tqg8XirvjJbUw69ApMHYpQ== richard@araminta');
ok($k2->{type} eq "rsa", "type should be 'rsa', is '$k2->{type}'");
ok($k2->{protocol} == 2, "protocol should be 2, is $k2->{protocol}");
ok($k2->{name} eq "richard\@araminta", "type should be 'richard\@araminta', is '$k2->{name}'");
ok($k2->{bits} == 2048, "bits should be 2048, is $k2->{bits}");
ok($k2->{strength} == 112, "strength should be 112, is $k2->{strength}");
ok($k2->{e} eq '23', "public exponent should be (hex) 23, is $k2->{e}");
ok($k2->get_id() eq 'c04c3ed920121b5becc5b91927b2ece03c93496b', "id should be c04c3ed920121b5becc5b91927b2ece03c93496b, is ".$k2->get_id());

# Same key expressed in protocol 1 syntax
my $k2a = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "2048 35 24680595477525071228666633858974963585906849900974439839578949001692366606597465594249720474414183481002713560548983496180359661349390548247578966073578565758901345239741420806584897592905957641342654084126808544821100685977418731234538635643841034986124074900753190550499024384177037489585685752810877026168072619161557543447153927029641776563335582354757144867142251742199586137289279340716248862111939672028058138328638468944710937041913535022007325231825313139914727487113071915288479232035741967531919174623541376962435078203579995261966542129398869680459166135674190480851510272383972134434068010705926951655589 whatever");
ok($k2a->get_id() eq 'c04c3ed920121b5becc5b91927b2ece03c93496b', "id should be c04c3ed920121b5becc5b91927b2ece03c93496b, is ".$k2a->get_id());
ok($k2 == $k2a);

# Protocol version 2: DSA
my $k3 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ssh-dss AAAAB3NzaC1kc3MAAACBAPJb8fEipFHAKxP3B2d8eSyf5tGQiAQGdzlxjjaZJCDF6kw3Z7iH2ywWHHlt0IlQRVB20my7YXs1jwj/k4zYYihYL5iY4Lqux2PuTCCRy+ts2XbJjYdZJs0SIERMOv6qunzjgFHFQNNYCPgNxxdz2av9eKE4aUGYhYBSdmXmbJrzAAAAFQDoGzAwGXOeXKV80CBSGcn1IkS2twAAAIEA56C2T+nfoX7odyP1ECyfALq+/xXaAHDjckRESv4PXVx321znHGAqia8EixmIaGE7hpFTK9EkeTUx7XoNEE2fWAMV7PP/A6QDsB6fR6adi2PqPn2SnnPYraoLcpp8hK0kBC33ua8vxGE6dgf7gRf3xOUWt7X9YP0BY6kxaHyGKEIAAACBAJHF/JJiC7p2MMtgIo29g5wzLXo+9aVsRSknJu/G0fZTm/x1PNU0XOT9zo29TkFFymLU+YTGxwABLoZOnQxwTeKkJhX21vlrpCHDGRejY6ARSzm6dqBJpBKs9sMoJGITi4LkL5+ce9cwYOL5DJSvDVMkoNUbGRVIRMuvCeSJTr/p root\@araminta");
ok($k3->{type} eq "dsa", "type should be 'dsa', is '$k3->{type}'");
ok($k3->{protocol} == 2, "protocol should be 2, is $k3->{protocol}");
ok($k3->{name} eq "root\@araminta", "type should be 'root\@araminta', is '$k3->{name}'");
ok($k3->{bits} == 1024, "bits should be 1024, is $k3->{bits}");
ok($k3->{strength} == 80, "strength should be 80, is $k3->{strength}");
ok($k3->get_id() eq '68a87f52b45f43e8286596fe72a2de174b8db21f', "id should be 68a87f52b45f43e8286596fe72a2de174b8db21f, is ".$k3->get_id());

# Protocol version 2: ECDSA
my $k4 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBAk1wsDsaOJ27QqV3j3ruRphhtaH2dxYX9H1dTlk9ViW9RxamlpXj1Hksb45wyVwJTKukIq5Q+eVIwogjMO26c0= richard\@araminta-ec256");
ok($k4->{type} eq "ecdsa", "type should be 'ecdsa', is '$k4->{type}'");
ok($k4->{protocol} == 2, "protocol should be 2, is $k4->{protocol}");
ok($k4->{name} eq "richard\@araminta-ec256", "type should be 'richard\@araminta-ec256', is '$k4->{name}'");
ok($k4->{bits} == 256, "bits should be 256, is $k4->{bits}");
ok($k4->{strength} == 128, "strength should be 128, is $k4->{strength}");
ok($k4->get_id() eq '5232e5b87ae305602de4d7af443d3b56e52d4eed', "id should be 5232e5b87ae305602de4d7af443d3b56e52d4eed, is ".$k4->get_id());

# Protocol version 2: ED25519
my $k5 = Greenend::SSH::Key->new
    ('authorized_keys_line'
     => "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIL9xVKZrXpx+sMD0+P712BF2ah88jUUHG0bCBXBkKg9r richard\@araminta-ed25519");
ok($k5->{type} eq "ed25519", "type should be 'ed25519', is '$k5->{type}'");
ok($k5->{protocol} == 2, "protocol should be 2, is $k5->{protocol}");
ok($k5->{name} eq "richard\@araminta-ed25519", "type should be 'richard\@araminta-ed25519', is '$k5->{name}'");
ok($k5->{bits} == 256, "bits should be 256, is $k5->{bits}");
ok($k5->{strength} == 128, "strength should be 128, is $k5->{strength}");
ok($k5->get_id() eq '20d4f4595248c9c458e63737c3ab604507de8101', "id should be , is 20d4f4595248c9c458e63737c3ab604507de8101".$k5->get_id());

my @keys = Greenend::SSH::Key::all_keys();
ok(@keys == 5);
ok($keys[0] == $k5);
ok($keys[1] == $k4);
ok($keys[2] == $k3);
ok($keys[3] == $k2);
ok($keys[4] == $k1);
