# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(args-limit) begin
(args-limit) success. at least 64 command line arguments are supported.
(args-limit) success. arguments with at least 100 bytes are supported.
(args-limit) end
EOF
pass;
