#!/bin/bash

result1=0
result2=0

#Source the 2nd script, i.e. . test2.sh and it will run in the same shell.
. ./build.sh

# 在中括號 [] 內的每個元件都需要有空白鍵來分隔；
# 在中括號內的變數，最好都以雙引號括號起來；
# 在中括號內的常數，最好都以單或雙引號括號起來。
# Arithmetic in bash uses $((...)) syntax.
errorlevel=$((result1 + result2))
if [ $errorlevel == 0 ] && [ -a ./aout.exe ]; then
	./aout.exe
	echo ====== aout.exe Done!! Errorlevel = $? ======
else
	echo NOT execute aout.exe ...
fi
