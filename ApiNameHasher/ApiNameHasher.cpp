// ApiNameHasher.cpp : Defines the entry point for the console application.
//

#include <Windows.h>
#include <stdio.h>


DWORD BlackBubbleHasher(char* pszApiName);
DWORD LazarusHasher(char* pszApiName);
void PrintHashesForDll(char *pszDllName, char*pszshortname);
DWORD RvaToOffset(LPVOID dwFileBase, DWORD Rva);
void PrintHashesForAllSystemDlls();
void PrintHashesForCommonDlls();

int main(int argc, char** argv)
{
 
    PrintHashesForCommonDlls();
    return 0;
}

void PrintHashesForAllSystemDlls()
{
	   HANDLE hFind = INVALID_HANDLE_VALUE;
    BOOL retVal = FALSE;
    char szFilePath[MAX_PATH] = { 0 };
    char szFileBaseName[MAX_PATH] = { 0 };
    WIN32_FIND_DATAA FindData = { 0 };

    hFind = FindFirstFileA("C:\\Windows\\System32\\*.dll", &FindData);

    if (hFind == INVALID_HANDLE_VALUE)
    {
        printf("FindFirstFile error: 0x%08X\r\n", GetLastError());
        return;
    }

    do
    {
        if (!(FindData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY))
        {
            memcpy(szFileBaseName, FindData.cFileName, (strlen(FindData.cFileName) - 4));
            //Quickie conversion on the basename. On filenames like "Windows.ApplicationModel.Core.dll", replace the dots in the basename to underscore
            for (int i = 0; i < strlen(szFileBaseName); i++)
            {
                if (szFileBaseName[i] == '.')
                {
                    szFileBaseName[i] = '_';
                }
            }

            //printf("Checking %s\r\n", FindData.cFileName);
            strcat(szFilePath, "C:\\Windows\\System32\\");
            strcat(szFilePath, FindData.cFileName);

            PrintHashesForDll(szFilePath, szFileBaseName);
        }


        memset(szFilePath, 0, sizeof(szFilePath));
        memset(szFileBaseName, 0, sizeof(szFileBaseName));
    } while (FindNextFileA(hFind, &FindData));
}

void PrintHashesForCommonDlls()
{

	PrintHashesForDll("c:\\windows\\system32\\kernel32.dll", "kernel32");
	PrintHashesForDll("c:\\windows\\system32\\advapi32.dll", "advapi32");
    PrintHashesForDll("c:\\windows\\system32\\user32.dll", "user32");
    PrintHashesForDll("c:\\windows\\system32\\ws2_32.dll", "ws2_32");
    PrintHashesForDll("c:\\windows\\system32\\ntdll.dll", "ntdll");
    PrintHashesForDll("c:\\windows\\system32\\winsta.dll", "winsta");
    PrintHashesForDll("c:\\windows\\system32\\shell32.dll", "shell32");
    PrintHashesForDll("c:\\windows\\system32\\wininet.dll", "wininet");
    PrintHashesForDll("c:\\windows\\system32\\urlmon.dll","urlmon");
    PrintHashesForDll("c:\\windows\\system32\\ole32.dll","ole32");
    PrintHashesForDll("c:\\windows\\system32\\winhttp.dll", "winhttp");
	
}

void PrintHashesForDll(char *pszDllName, char *pszShortName)
{

		PDWORD Address, Name;
		PWORD Ordinal;

		DWORD i;
        HMODULE hLib = LoadLibraryExA(pszDllName, NULL, DONT_RESOLVE_DLL_REFERENCES);

        if (hLib == NULL)
        {
            fprintf(stderr, "Unable to load %s, error 0x%08X\r\n", pszDllName, GetLastError());
            return;
        }


        LPVOID hFile = (LPVOID)hLib;

        PIMAGE_DOS_HEADER pDos = (PIMAGE_DOS_HEADER)hLib;
        PIMAGE_NT_HEADERS pNt = (PIMAGE_NT_HEADERS) (BYTE *)((DWORD)hFile + pDos->e_lfanew);
		PIMAGE_DATA_DIRECTORY pExportDataDirectory;
		PIMAGE_EXPORT_DIRECTORY pExportDirectory;
		
		pExportDataDirectory = (PIMAGE_DATA_DIRECTORY) &pNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];

		if (pExportDataDirectory->VirtualAddress == 0)
		{
            FreeLibrary(hLib);
			return;
		}
		pExportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE *)(DWORD)hLib + pExportDataDirectory->VirtualAddress);

		Address = (PDWORD)((BYTE*)(DWORD)hLib + pExportDirectory->AddressOfFunctions);
		Name = (PDWORD)((BYTE*)(DWORD)hLib + pExportDirectory->AddressOfNames);

		Ordinal = (PWORD)((BYTE*)(DWORD)hLib + pExportDirectory->AddressOfNameOrdinals);

		for (i = 0; i<pExportDirectory->NumberOfNames; i++)
		{
			DWORD dwFoo = BlackBubbleHasher((char*)((BYTE*)(DWORD)hFile + Name[i]));
			printf("#define %s_%s 0x%08X\r\n", pszShortName, (char*)((BYTE*)(DWORD)hLib + Name[i]), dwFoo);
		}

        FreeLibrary(hLib);
		return;

}

DWORD LazarusHasher(char* pszApiName)
{
    DWORD dwFoo = 0x2dbb955;
    DWORD dwLen = strlen(pszApiName);
    unsigned char bVar2 = 0;
    unsigned char bVar5 = 0;

    __asm {
        mov edx, dwFoo;
        mov esi ,[pszApiName];
        mov cl, byte ptr[esi];
    __lele:
        mov edi, edx;
        mov ebx, edx;
        shl edi, 0x5;
        sar ebx, 0x2;
        movsx ecx, cl;
        add edi, ebx;
        add edi, ecx;
        mov cl, byte ptr[esi + 1];
        inc esi;
        xor edx, edi;
        test cl, cl;
        jnz __lele;
        mov dwFoo, edx;
    }
    return dwFoo;

}

DWORD BlackBubbleHasher(char *pszApiName)
{
    DWORD dwLol = 0xd3f505f9;
	DWORD dwFoo = 0x811c9dc5;
    DWORD dwLen = strlen(pszApiName);
    DWORD dwLel = 0;
    DWORD dwIndex = 0;
    unsigned char bVar2 = 0;
    unsigned char bVar5 = 0;
  
    for (int i = 0; i < dwLen; i++)
    {
        dwLel = (byte)pszApiName[i];
        dwFoo = (dwFoo ^ dwLel) * 0x1000193;
    }
    
    do
    {
        dwFoo = (dwFoo ^((byte*)&dwLol)[dwIndex]) * 0x1000193;
        dwIndex++;
    } while (dwIndex < dwLen);

	return dwFoo;

}

DWORD RvaToOffset(LPVOID dwFileBase, DWORD Rva)
{

        IMAGE_DOS_HEADER *DosHeader;
        IMAGE_NT_HEADERS * MainPEHeader;
        LPVOID PEHeader = NULL;
        LPVOID pSection = NULL;
        IMAGE_SECTION_HEADER* Section=NULL;
        long NumberOfSections;

        DosHeader = (IMAGE_DOS_HEADER*)dwFileBase;
        PEHeader = (LPVOID)((DWORD)dwFileBase + (DWORD)DosHeader->e_lfanew);

        MainPEHeader = (IMAGE_NT_HEADERS*)PEHeader;
        NumberOfSections = MainPEHeader->FileHeader.NumberOfSections;

        pSection = (LPVOID)((DWORD)PEHeader + sizeof(IMAGE_NT_HEADERS));

        for (int Count=0;Count <= NumberOfSections;Count++)
        {

                Section = (IMAGE_SECTION_HEADER*)pSection;
                if (Rva >= Section->VirtualAddress)
                {
                        if (Rva < (Section->VirtualAddress + Section->SizeOfRawData))
                        {
                                // it's in this section..
                                long AddressDiff = Rva - Section->VirtualAddress;
                                return (Section->PointerToRawData + AddressDiff);

                        }
                }

        pSection = (LPVOID)((DWORD)pSection + sizeof(IMAGE_SECTION_HEADER));

        }

        return 0;

}
