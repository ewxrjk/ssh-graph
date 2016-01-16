#! /usr/bin/perl -w
#
# Copyright © 2013-2016 Richard Kettlewell
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

use strict;
use warnings;
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME                => 'ssh-graph',
    AUTHOR              => q{Richard Kettlewell <rjk@terraraq.org.uk>},
    VERSION_FROM        => 'bin/ssh-graph',
    ABSTRACT            => "Graph SSH key distribution and check for anomalies",
    LICENSE             => 'gpl',
    EXE_FILES => [ 'bin/ssh-graph' ],
    dist                => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
);
