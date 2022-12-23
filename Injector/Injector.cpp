// Injector.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <Windows.h>
#include <iostream>
#include <string>
#include <tlhelp32.h>
#include <cstring>

HANDLE getProcessHandle(std::string processName) {
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);

    if (Process32First(snapshot, &entry) == TRUE)
    {
        while (Process32Next(snapshot, &entry) == TRUE)
        {
            std::string cName = std::string(entry.szExeFile);
            if (cName == processName)
            {
                HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, entry.th32ProcessID);

                // Do stuff..
                return hProcess;
                //CloseHandle(hProcess);
            }
        }
    }

    //CloseHandle(snapshot);
    return NULL;
}
// Function to inject a DLL into a process
bool InjectDllIntoProcess(HANDLE ProcessHandle, const char* DllPath)
{
    // Get the address of the LoadLibrary function in the target process
    LPTHREAD_START_ROUTINE LoadLibraryAddress = (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle("kernel32.dll"), "LoadLibraryA");
    if (LoadLibraryAddress == NULL)
    {
        wprintf(L"Failed to get address of LoadLibrary function\n");
        return false;
    }

    // Allocate memory in the target process to hold the DLL's path
    auto DllPathLength = strlen(DllPath);
    LPVOID DllPathAddress = VirtualAllocEx(ProcessHandle, NULL, DllPathLength, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (DllPathAddress == NULL)
    {
        wprintf(L"Failed to allocate memory in target process\n");
        return false;
    }

    // Write the DLL's path into the allocated memory in the target process
    if (!WriteProcessMemory(ProcessHandle, DllPathAddress, DllPath, DllPathLength, nullptr))
    {
        wprintf(L"Failed to write DLL path to target process memory\n");
        return false;
    }

    // Create a new thread in the target process, and pass the DLL's path as an argument to the LoadLibrary function
    HANDLE ThreadHandle = CreateRemoteThread(ProcessHandle, NULL, 0, LoadLibraryAddress, DllPathAddress, NULL, NULL);
    if (ThreadHandle == NULL)
    {
        wprintf(L"Failed to create remote thread in target process\n");
        return false;
    }

    // Wait for the thread to finish executing
    WaitForSingleObject(ThreadHandle, INFINITE);

    // Get the return value of the LoadLibrary function (should be the handle to the loaded DLL)
    DWORD DllHandle = 0;
    GetExitCodeThread(ThreadHandle, &DllHandle);

    // Free the allocated memory in the target process
    VirtualFreeEx(ProcessHandle, DllPathAddress, 0, MEM_RELEASE);

    // Close the thread handle
    CloseHandle(ThreadHandle);

    return DllHandle != 0;
}


int main(int argc, char* argv[])
{
    int argumentCount = argc;
    if (argumentCount != 3) {
        std::cout << "Provide correct arguments" << std::endl;
        return 0;
    }

    std::string exeName = argv[1];
    std::string dllPath = argv[2];

    std::cout << "~~Injector~~" << std::endl;
    std::cout << "Target: " << exeName << std::endl;
    std::cout << "Dll path: " << dllPath << std::endl;

    HANDLE proc = getProcessHandle(exeName);
    if (proc == NULL) {
        std::cout << "No process found" << std::endl;
        return 0;
    }
    InjectDllIntoProcess(proc, argv[2]);

    Sleep(10000);
    return 0;
}
