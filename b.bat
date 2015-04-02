cl /Ox /Os /GS- /GF /EHsc /DNDEBUG /MT enc.cpp md5c.c random.cpp setargv.obj advapi32.lib /link /ALIGN:4096 /OPT:ICF
\sw\upx\upx enc.exe

