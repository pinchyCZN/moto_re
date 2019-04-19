@echo off

yasm  -o test.obj -w -f win32 CRACKED_MOTO.asm
rem yasm  -o test.obj -w -f win32 fixed2.asm


link @link.txt
rem golink @glink.txt