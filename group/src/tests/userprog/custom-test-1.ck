# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(custom-test-1) begin
(custom-test-1) end
custom-test-1: exit(0)
EOF
pass;
