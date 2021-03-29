#!/bin/bash

echo ====== Start "build.sh" ======

make -f ./Makefiles/_1_UpdateMFiles.mak -I Makefiles MY_OS=LINUX
result1=$?

make Build_All -f ./Makefiles/_2_Build.mak -I Makefiles MY_OS=LINUX
result2=$?

echo ====== Build Done!! Errorlevel = $result1, $result2 ======
