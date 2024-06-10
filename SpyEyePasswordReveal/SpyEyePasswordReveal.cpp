#include "stdafx.h"
#include <windows.h>
#include <stdio.h>

#define BUFSIZE 1024
#define DLL_NAME "SpyVsSpy.dll"
char *VERSION = "1.0";

BOOL InjectDLL(DWORD ProcessID);
DWORD WINAPI PipeThread(LPVOID lParam);
void EnableDebugPriv();

int main(int argc, char* argv[])
{
        printf("SpyEye Password Extractor %s (c) 2011 Fitsec Ltd\r\n",VERSION);
        if(argc != 2){
                printf("usage: SpyEyePasswordReveal.exe <SpyEye binary>\r\n");
                printf("NOTE: THIS TOOL RUNS THE LIVE MALWARE SO BE CAREFULL!!!\r\n");
                return(0);
        }
		EnableDebugPriv();
        PROCESS_INFORMATION pi;
        STARTUPINFO si;
        ZeroMemory( &si, sizeof(si) );
	    si.cb = sizeof(si);
		ZeroMemory( &pi, sizeof(pi) );
        //Safeguard, check for existence of the dll...
        HANDLE puhveli = CreateFile(DLL_NAME,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
        if(puhveli == INVALID_HANDLE_VALUE)
        {
                printf("[!] Could not locate SpyVsSpy.dll, aborting\r\n");
                ExitProcess(-1);
        }
        else
        {
                CloseHandle(puhveli);
        }
        DWORD dwThreadId = 0;
        printf("[+] Starting up %s for password extraction\r\n",argv[1]);
        CreateProcess(argv[1],NULL,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi);
        //Inject here
        if(InjectDLL(pi.dwProcessId))
        {
                ResumeThread(pi.hThread);
        }
        else
        {
                TerminateProcess(pi.hProcess,0);
        }
        Sleep(2500);
        return 0;
}

BOOL InjectDLL(DWORD ProcessID)
{
   HANDLE Proc;
   char buf[50]={0};
   LPVOID RemoteString, LoadLibAddy;

   if(!ProcessID)
      return false;

   Proc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, ProcessID);

   if(!Proc)
   {
      printf("[!] OpenProcess() failed: %d, terminating the process...\r\n", GetLastError());
      return false;
   }

   LoadLibAddy = (LPVOID)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");

   RemoteString = (LPVOID)VirtualAllocEx(Proc, NULL, strlen(DLL_NAME), MEM_RESERVE|MEM_COMMIT, PAGE_READWRITE);
   WriteProcessMemory(Proc, (LPVOID)RemoteString, DLL_NAME,strlen(DLL_NAME), NULL);
   CreateRemoteThread(Proc, NULL, NULL, (LPTHREAD_START_ROUTINE)LoadLibAddy, (LPVOID)RemoteString, NULL, NULL);

   CloseHandle(Proc);
   return true;
}
void EnableDebugPriv() {
    HANDLE hToken;
    LUID luid;
    TOKEN_PRIVILEGES tkp;

    OpenProcessToken( GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken );

    LookupPrivilegeValue( NULL, SE_DEBUG_NAME, &luid );

    tkp.PrivilegeCount = 1;
    tkp.Privileges[0].Luid = luid;
    tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    AdjustTokenPrivileges( hToken, false, &tkp, sizeof( tkp ), NULL, NULL );

    CloseHandle( hToken );
}
