# -*- perl -*-
use strict;
use warnings;
use tests::tests;
check_expected (IGNORE_EXIT_CODES => 1, [<<'EOF']);
(mmap-lazy-seq) begin
(mmap-lazy-seq) create "sample.txt"
(mmap-lazy-seq) open "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) mmap "sample.txt"
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) compare read data against written data
(mmap-lazy-seq) end
EOF
pass;
