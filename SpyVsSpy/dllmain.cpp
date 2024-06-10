#include <stdio.h>
#include <wchar.h>
#include <windows.h>
#include <Tlhelp32.h>
#include <malloc.h>

unsigned char *buf;
char msg[100];
char foobuf[258];
DWORD bwritten;
HANDLE hLog;

BOOL ScanSpyEye();

BOOL APIENTRY DllMain( HANDLE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                                         )
{
		if(ul_reason_for_call == DLL_PROCESS_ATTACH)
		{
			CreateDirectory("c:\\SpyVsSpy", NULL);
			hLog = CreateFile("c:\\SpyVsSpy\\spyeye.log",GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
            SetFilePointer(hLog,0,0,FILE_END);
            sprintf_s(msg,"Waiting for process death...\r\n");
            WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
            memset(msg,0,100);
        }
        if(ul_reason_for_call == DLL_PROCESS_DETACH){
			      ScanSpyEye();     
        }
        return TRUE;
}


BOOL ScanSpyEye()
{
	SYSTEM_INFO     si;
	MEMORY_BASIC_INFORMATION mbi;
    DWORD bytesread = 0;
    DWORD base = 0x00100000;
    DWORD oldProtect;
    GetSystemInfo(&si);
    int startmark = 0;
    BOOL startfound = FALSE;
    BOOL wasallocated = FALSE;
    SetFilePointer(hLog,0,0,FILE_END);
    sprintf_s(msg,"process death triggered, scanning...\r\n");
    WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
    memset(msg,0,100);
    
	while ((LPVOID)base < si.lpMaximumApplicationAddress)
    {
		if(VirtualQuery((LPVOID)base,&mbi,sizeof(mbi)) != 0)
        {
			if(mbi.State == MEM_COMMIT)
            {
				if(VirtualProtect((LPVOID)base,mbi.RegionSize,PAGE_EXECUTE_READWRITE,&oldProtect) == 0)
				{

				}
                buf = (unsigned char *)VirtualAlloc(NULL,mbi.RegionSize,MEM_COMMIT,PAGE_READWRITE);
                wasallocated = TRUE;
                DWORD retval = ReadProcessMemory((HANDLE)-1,(LPCVOID)base,buf,mbi.RegionSize,&bytesread);
                base = base+mbi.RegionSize;
                if(retval == 0) 
                {
					sprintf_s(msg,"ReadProcessMemory returned error 0x%08x\r\n",GetLastError());
                    WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
                    memset(msg,0,100);
				}
	
				for(startmark=0;startmark<=mbi.RegionSize-100;startmark++)
                {
					DWORD counter = 0;
                    if(!startfound )
                    {
						for(int i = 0; i < 32;i++)
                        {
							if((buf[startmark + i] >= 0x30 && buf[startmark + i] <= 0x39) || (buf[startmark + i] >= 'A' && buf[startmark + i] <= 'F'))
							{
								if(i == 31)
								{
									startfound = true;
									sprintf_s(msg,"First chars: %02X %02X %02X %02X %02X\r\n",buf[startmark],buf[startmark+1],buf[startmark+2],buf[startmark+3],buf[startmark+4]);
									WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
									memset(msg,0,100);
									break;
								}
							}
							else
							{
								break;
							}
						}
             
						continue;

					}
                    else
					{
						/*
                         * Dump the key and mark this as version1
                         */
						sprintf_s(msg,"SpyEye configuration password found: , dumping...\r\n");
                        WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
                        memset(msg,0,100);
                        startmark = startmark - 1;
                        DWORD written;
						char eol[] = {'\r','\n'};
                        //memcpy(keybuf,&buf[startmark],32);
						HANDLE logHandle = CreateFile("C:\\spyvsspy\\SpyKeys.bin",GENERIC_WRITE,FILE_SHARE_READ,NULL,OPEN_ALWAYS,FILE_ATTRIBUTE_NORMAL,NULL);
						SetFilePointer(logHandle,0,0,FILE_END);
                        WriteFile(logHandle, &buf[startmark], 32, &written, NULL);
						WriteFile(logHandle, eol, 2, &written, NULL);
                        CloseHandle(logHandle);
						startfound = false;
                        break;
					}
				}
			}
        }
        if(wasallocated)
        {
        /*      sprintf(msg,"Freeing %d allocated bytes.\r\n",mbi.RegionSize);
                WriteFile(hLog,msg,strlen(msg),&bwritten,NULL);
                memset(msg,0,100);*/
                VirtualFree(buf,0,MEM_RELEASE);
                wasallocated = FALSE;
        }
        base = base+mbi.RegionSize+0x1000;
} //end while

        return FALSE;
}
