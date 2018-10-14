.386
.model flat,stdcall
option casemap:none
;在win10环境下 用masm32编译器链接器
;ml -c -coff helloworld.asm
;生成helloworld.obj文件
;link -subsystem:console virus.obj
;生成helloworld.exe即为病毒母体程序


include windows.inc 
include user32.inc
includelib user32.lib
include kernel32.inc
includelib kernel32.lib


.code
entery:
	jmp start
szText db 'helloworld',0

start:
	invoke MessageBox,NULL,offset szText,NULL,MB_OK
	mov ebx,ebp
	invoke ExitProcess,NULL
end entery