#!/bin/bash

PIN="pin -t ../../proj1_sol.so -- "

echo -e "\n\n[Run date..]"
$PIN ./date

echo -e "\n\n[Run echo..]"
$PIN ./echo "Hello World!"

echo -e "\n\n[Run grep..]"
$PIN ./grep main test.c

echo -e "\n\n[Run gcc..]"
$PIN ./gcc ./test.c -g -o test

echo -e "\n\n[Run hello..]"
$PIN ./hello

echo -e "\n\n[Run ls..]"
$PIN ./ls

echo -e "\n\n[Run tar..]"
$PIN ./tar czvf testfile.tar.gz testfile

echo -e "[Run bzip2..]"
$PIN ./bzip2 ./testfile

echo -e "\n\n[Run bunzip2..]"
$PIN ./bunzip2 ./testfile.bz2

