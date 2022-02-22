#!/bin/bash

PIN="pin -t ../../proj1_sol.so -- "

echo -e "[Run stack_overflow..]"
echo "$PIN ./stack_overflow $(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*36 + "\x80\xf5\xff\xbf"')"
$PIN ./stack_overflow $(python -c 'print "\x31\xc0\x99\x50\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x50\x53\x89\xe1\xb0\x0b\xcd\x80" + "A"*36 + "\x80\xf5\xff\xbf"')

echo -e "\n\n[Run rop_dynamic..]"
echo "$PIN ./rop_dynamic "`python ./rop_dynamic.py`""
$PIN ./rop_dynamic "`python ./rop_dynamic.py`"

echo -e "\n\n[Run stack_overflow_gets..]"
echo "$PIN ./stack_overflow_gets < stack_overflow.input"
$PIN ./stack_overflow_gets < stack_overflow.input

echo -e "\n\n[Run stack_overflow_fgets..]"
echo "$PIN ./stack_overflow_fgets < stack_overflow.input"
$PIN ./stack_overflow_fgets < stack_overflow.input

echo -e "\n\n[Run overflow_fncptr..]"
echo "$PIN ./overflow_fncptr < ./overflow_fncptr.input"
$PIN ./overflow_fncptr < ./overflow_fncptr.input

