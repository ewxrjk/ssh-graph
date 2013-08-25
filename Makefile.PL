#! /usr/bin/perl -w
use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'ssh-graph',
    AUTHOR              => q{Richard Kettlewell <rjk@terraraq.org.uk>},
    VERSION_FROM        => 'bin/ssh-graph',
    ABSTRACT            => "Graph SSH key distribution and check for anomalies",
    LICENSE             => 'gpl',
#    MAN1PODS => {
#        'bin/viewgcov' => 'blib/man1/viewgcov',
#    },
    EXE_FILES => [ 'bin/ssh-graph' ],
#    PREREQ_PM => {
#        'Gtk2' => 0,
#    },
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
#    clean               => { FILES => 'Greenend-ViewGCOV-Foo-*' },
);
