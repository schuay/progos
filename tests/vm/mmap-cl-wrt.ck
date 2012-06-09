# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(mmap-cl-wrt) begin
(mmap-cl-wrt) create "dummy.txt"
(mmap-cl-wrt) create "sample.txt"
(mmap-cl-wrt) open "dummy.txt"
(mmap-cl-wrt) mmap "dummy.txt"
(mmap-cl-wrt) open "sample.txt"
(mmap-cl-wrt) open "sample.txt" for verification
(mmap-cl-wrt) verified contents of "sample.txt"
(mmap-cl-wrt) close "sample.txt"
(mmap-cl-wrt) end
EOF
pass;
