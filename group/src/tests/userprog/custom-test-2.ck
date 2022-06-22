# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected ([<<'EOF']);
(custom-test-2) begin
(custom-test-2) end
custom-test-2: exit(0)
EOF
pass;
