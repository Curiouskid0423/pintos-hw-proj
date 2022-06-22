# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_USER_FAULTS => 1, [<<'EOF']);
(proj2-custom) begin
(proj2-custom) Main started.
(proj2-custom) first thread can join
(proj2-custom) second thread should fail
(proj2-custom) end
proj2-custom: exit(0)
EOF
pass;
