# asmvirus
a usual virus in win10 platform(also in winNT)
masm32编译链接环境

编译链接器下载地址：http://www.masm32.com/

病毒实现功能： 
 1. 病毒源程序是一个exe文件 ，被执行后 会弹出一个对话框
 2. 当病毒被执行后，会查找当前目录下所有exe文件，并将本身的功能插入到exe文件中，原exe程序功能不受影响。
 3. 被感染exe程序在执行前会执行和病毒源程序相同的功能 。
 

本程序在win10环境下能感染大部分32位exe程序， 如果要移植到 win7系统下需要修改 其中一个api函数的名字， （后缀好像由w改为a）

本程序暂时的病毒发作状况为弹出一个对话框， 如果通过合适的修改，可以在本人标记的位置中添加任何shellcode，并实现自己的病毒作用功能。#
# 编译环境
在win10环境下 用masm32编译器链接器

ml -c -coff virus.asm

生成virus.obj文件

link -subsystem:console virus.obj

生成virus.exe即 为病毒母体程序
