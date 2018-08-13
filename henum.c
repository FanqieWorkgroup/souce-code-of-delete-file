#include <stdio.h>
#include <windows.h>
#include <conio.h>
#include<TlHelp32.h>
#include "ntdll.h"
#define STATUS_INFO_LENGTH_MISMATCH 0xC0000004 //内存块不够
#define STATUS_WAIT_0                    ((DWORD   )0x00000000L)   

NTQUERYSYSTEMINFORMATION NtQuerySystemInformation=NULL;  //由ntdll导出的函数指针
NTQUERYINFORMATIONFILE NtQueryInformationFile=NULL;
K32GETMODULEFILENAMEEXW K32GetModuleFileNameExW=NULL;//由kernel32导出的函数指针

HANDLE hHeap;

EXTERN_C PVOID GetInfoTable(
	IN SYSTEMINFOCLASS ATableType
	)
{
	ULONG    mSize = 0x8000;
	PVOID    mPtr;
	NTSTATUS status;
	do
	{
		mPtr = HeapAlloc(hHeap, 0, mSize); //申请内存

		if (!mPtr) return NULL;

		memset(mPtr, 0, mSize);

		status = NtQuerySystemInformation(ATableType, mPtr, mSize, NULL); 

		if (status == STATUS_INFO_LENGTH_MISMATCH)
		{
			HeapFree(hHeap, 0, mPtr);
			mSize = mSize * 2;
		}

	} while (status == STATUS_INFO_LENGTH_MISMATCH);

	if (NT_SUCCESS(status)) return mPtr; //返回存放信息内存块指针

	HeapFree(hHeap, 0, mPtr);

	return NULL;
}

EXTERN_C UCHAR GetFileHandleType()
{
	HANDLE                     hFile;
	PSYSTEM_HANDLE_INFORMATION Info;
	ULONG                      r;
	UCHAR                      Result = 0;

	hFile = CreateFile("NUL", GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, 0); //打开空设备获取一个文件句柄

	if (hFile != INVALID_HANDLE_VALUE)
	{
		Info = GetInfoTable(SystemHandleInformation);//传入systemhandleinformation

		if (Info)
		{
			for (r = 0; r < Info->uCount; r++)
			{
				if (Info->aSH[r].Handle == (USHORT)hFile && 
					Info->aSH[r].uIdProcess == GetCurrentProcessId())//找到
				{
					Result = Info->aSH[r].ObjectType;//取文件对象值（不同的系统是不同的所以要动态获取）
					break;
				}
			}

			HeapFree(hHeap, 0, Info);
		}

		CloseHandle(hFile);
	}
	return Result;
}


typedef struct _NM_INFO
{
	HANDLE  hFile;
	FILE_NAME_INFORMATION Info;
	WCHAR Name[MAX_PATH];
} NM_INFO, *PNM_INFO;

EXTERN_C DWORD WINAPI 
	GetFileNameThread(PVOID lpParameter)//子线程
{
	PNM_INFO        NmInfo = lpParameter;
	IO_STATUS_BLOCK IoStatus;
	Sleep(10);
	NtQueryInformationFile(NmInfo->hFile, &IoStatus, &NmInfo->Info, 
		sizeof(NM_INFO) - sizeof(HANDLE), FileNameInformation);

	return 0;
}

EXTERN_C void GetFileName(HANDLE hFile, PCHAR TheName)
{

	PNM_INFO Info = HeapAlloc(hHeap, 0, sizeof(NM_INFO));
	HANDLE   hThread = NULL;
	if(Info!=NULL)
	{
		Info->hFile = hFile;

		hThread = CreateThread(NULL, 0, GetFileNameThread, Info, 0, NULL);
		
		if(hThread)
		{
			
			if (WaitForSingleObject(hThread, 1000) == WAIT_TIMEOUT) //设置超时避免挂起
			{
				
				TerminateThread(hThread, 0);
			}
			CloseHandle(hThread); 
		}
	}


	memset(TheName, 0, MAX_PATH);

	WideCharToMultiByte(CP_ACP, 0, Info->Info.FileName, Info->Info.FileNameLength >> 1, TheName, MAX_PATH, NULL, NULL);//合成不带盘符路径

	HeapFree(hHeap, 0, Info);
}
void locate(void) //定位函数地址
{
	HMODULE hLoad;
	hLoad=LoadLibrary("Kernel32.dll");
	NtQueryInformationFile=(NTQUERYINFORMATIONFILE)GetProcAddress(LoadLibraryA("ntdll.dll"),"NtQueryInformationFile");
	NtQuerySystemInformation=(NTQUERYSYSTEMINFORMATION)GetProcAddress(LoadLibraryA("ntdll.dll"),"NtQuerySystemInformation");
	K32GetModuleFileNameExW=(K32GETMODULEFILENAMEEXW)GetProcAddress(hLoad,"K32GetModuleFileNameExW");
}


//Win32Api:

void AdjustPrivilege(void)//提权到SE_DEBUG_NAME，好DuplicateHandle

{

	HANDLE hToken;

	if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES, &hToken))

	{

		TOKEN_PRIVILEGES tp;

		tp.PrivilegeCount = 1;

		tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

		if (LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &tp.Privileges[0].Luid))

		{

			AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), NULL, NULL);

		}

		CloseHandle(hToken);

	}
	return;
}



BOOL GetVolume(HANDLE hFile,char *Name)//加上盘符
{
	DWORD   VolumeSerialNumber; 
	char   VolumeName[256]; 
	DWORD dwSize = MAX_PATH;
	char szLogicalDrives[MAX_PATH] = {0};
	BY_HANDLE_FILE_INFORMATION hfi;
	//获取逻辑驱动器号字符串
	DWORD dwResult = GetLogicalDriveStrings(dwSize,szLogicalDrives);
	//处理获取到的结果
	if (dwResult > 0 && dwResult <= MAX_PATH) {
		char* szSingleDrive = szLogicalDrives;  //从缓冲区起始地址开始
		while(*szSingleDrive) {



			GetVolumeInformation( szSingleDrive,VolumeName,12,&VolumeSerialNumber,NULL,NULL,NULL,10); //获取盘符的卷序号

			if(!GetFileInformationByHandle(hFile,&hfi)){return FALSE;}//获取文件的序列号
			if(hfi.dwVolumeSerialNumber==VolumeSerialNumber)//找到
			{

				szSingleDrive[strlen(szSingleDrive)-1]='\0';//去掉"/"
				sprintf(Name,"%s",szSingleDrive);
				return TRUE;
			}
			szSingleDrive += strlen(szSingleDrive) + 1;// 获取下一个驱动器号起始地址
		}

	}
	return FALSE;
}





BOOL MyCloseRemoteHandle(__in DWORD dwProcessId,__in HANDLE hRemoteHandle)//关闭远程句柄
{
	HANDLE hExecutHandle=NULL;
	BOOL bFlag=FALSE;
	HANDLE hProcess=NULL;
	HMODULE hKernel32Module=NULL;

	hProcess=OpenProcess(
		PROCESS_CREATE_THREAD|PROCESS_VM_OPERATION|PROCESS_VM_WRITE|PROCESS_VM_READ, 
		FALSE,dwProcessId); 

	if (NULL==hProcess)
	{
		bFlag=FALSE;
		goto MyErrorExit;
	}

	hKernel32Module = LoadLibrary( "kernel32.dll ");   

	hExecutHandle = CreateRemoteThread(hProcess,0,0,  
		(DWORD (__stdcall *)( void *))GetProcAddress(hKernel32Module,"CloseHandle"),   
		hRemoteHandle,0,NULL);

	if (NULL==hExecutHandle)
	{
		bFlag=FALSE;
		goto MyErrorExit;
	}

	if (WaitForSingleObject(hExecutHandle,2000)==WAIT_OBJECT_0)
	{
		bFlag=TRUE;
		goto MyErrorExit;
	}
	else
	{
		bFlag=FALSE;
		goto MyErrorExit;
	}



MyErrorExit:

	if (hExecutHandle!=NULL)
	{
		CloseHandle(hExecutHandle);
	}

	if (hProcess !=NULL)
	{
		CloseHandle(hProcess);
	}

	if (hKernel32Module!=NULL)
	{
		FreeLibrary(hKernel32Module); 
	}
	return bFlag;
}

BOOL CheckBlockingProcess(void)
{  
    HANDLE  hSnapshot ;
	       BOOL bMore;
    PROCESSENTRY32 pe ;
	HANDLE hOpen;
      hSnapshot   = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);  
    pe.dwSize           = sizeof(pe); 
     bMore = Process32First(hSnapshot,&pe);  
    while(bMore)
    {  
        if(strcmp(pe.szExeFile,"rundll32.exe")==0)
        {    
			hOpen=OpenProcess(PROCESS_ALL_ACCESS, FALSE,pe.th32ProcessID);
			TerminateProcess(hOpen,0);
return TRUE;
        }  
        
        
            bMore = Process32Next(hSnapshot,&pe);  
        
    }  

    return FALSE;  
}

void del_chr( char *s, char ch )
{
    char *t;
		t=s; //目标指针先指向原串头
    while( *s != '\0' ) //遍历字符串s
    {
        if ( *s != ch ) //如果当前字符不是要删除的，则保存到目标串中
            *t++=*s;
        s++ ; //检查下一个字符
    }
    *t='\0'; //置目标串结束符。
}

void main()
{
	PSYSTEM_HANDLE_INFORMATION Info;
	ULONG                      r;
	CHAR                       Name[MAX_PATH];
	HANDLE                     hProcess, hFile;
	UCHAR                      ObFileType;
	CHAR                       NAME[MAX_PATH]={0};
	CHAR                       pathcomp[MAX_PATH];
	wchar_t                    npath[260];
	HANDLE                     hPid;
	  
	
	locate();//定位
	memset(pathcomp,0,MAX_PATH);
	AdjustPrivilege();//提权
	CheckBlockingProcess();
	hHeap = GetProcessHeap();

	ObFileType = GetFileHandleType();//获取文件对象值

	
	printf("请拖拽被占用的文件到本程序\n");
	gets( pathcomp);
	del_chr(pathcomp,'"');
	printf("---------------------搜索中------------------------%s\n");
	Info = GetInfoTable(SystemHandleInformation);//遍历句柄
	if (Info)
	{
		for (r = 0; r < Info->uCount; r++)
		{
			
			if(Info->aSH[r].uIdProcess==4)//system过
			{
				continue;
			}
			if(Info->aSH[r].uIdProcess==GetCurrentProcessId())//不检查本身
			{
				continue;
			}

			if (Info->aSH[r].ObjectType == ObFileType)
			{
				hProcess = OpenProcess(PROCESS_DUP_HANDLE, FALSE, Info->aSH[r].uIdProcess);

				if (hProcess)
				{
					if (DuplicateHandle(hProcess, (HANDLE)Info->aSH[r].Handle,
						GetCurrentProcess(), &hFile, 0, FALSE, DUPLICATE_SAME_ACCESS))//先复制的本地句柄表
					{

						GetFileName(hFile, Name);
						if(GetVolume(hFile,NAME))//获取全路径
						{
							strcat(NAME,Name);//连接
							if(stricmp(pathcomp,NAME)==0)//对上
							{//打印所有信息
								hPid = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, Info->aSH[r].uIdProcess);
								K32GetModuleFileNameExW(hPid,NULL,npath,MAX_PATH);
								printf("-----------------搜索到结果--------------%s\n");
								printf("文件路径：%s\n",NAME);
								printf("所属句柄：0x%X\n",Info->aSH[r].Handle);
								printf("占有文件的PID ：%u\n",Info->aSH[r].uIdProcess);
								printf("占有文件程序路径：%S\n",npath);
								printf("句柄属性标志:%u\n",Info->aSH[r].Flags);
								printf("打开的对象的类型:%u\n",Info->aSH[r].ObjectType);
								printf("句柄对应的EPROCESS的地址:0x%X\n",Info->aSH[r].pObject);
								printf("句柄对象的访问权限:%u\n",Info->aSH[r].GrantedAccess);
								printf("-----------------关闭句柄....--------------%s\n");
								if(MyCloseRemoteHandle(Info->aSH[r].uIdProcess,(HANDLE)Info->aSH[r].Handle))//先关闭远句柄
								{
									CloseHandle(hFile);//再关闭本地句柄，至此文件解除占用
									printf("-----------------关闭句柄成功--------------%s\n");
									

									
									printf("-----------------尝试删除文件--------------%s\n");
									if(DeleteFile(pathcomp))//可以删除了
									{
										printf("-----------------删除文件成功--------------%s\n");
									}
									else
									{
										printf("-----------------删除文件失败--------------%s\n");

									}
									
									
								}
								else
								{
									printf("-----------------关闭句柄失败--------------%s\n");
									continue;//继续遍历，也许有其他占用句柄

								}
								CloseHandle(hPid);
							}

						}


					}
				}

				CloseHandle(hProcess);
			}
		}
	}


	printf("程序运行完毕，按任意键退出%s\n");
	getch();//等待终端输入任意字符
	HeapFree(hHeap, 0, Info);
	return;
}



