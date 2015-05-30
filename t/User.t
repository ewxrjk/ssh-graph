use warnings;
use strict;
use Greenend::SSH::Key;
use Greenend::SSH::User;
use Test::Simple tests => 10;

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
ok($u2_known[0] == $k2);
ok($u2_known[1] == $k1);

$u2->add_accepts_key($k1);
my @u1_accepted = $u1->get_accepted_keys();
my @u2_accepted = $u2->get_accepted_keys();
ok(@u1_accepted == 0);
ok(@u2_accepted == 1);
ok($u2_accepted[0] == $k1);