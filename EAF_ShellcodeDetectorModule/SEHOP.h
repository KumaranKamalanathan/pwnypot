#pragma once
#include <Windows.h>
#include "ParseConfig.h"
#include "Hook.h"

#define PROCESS_EXECUTE_FLAG 0x22
#define SEHOP_FLAG 0x40


typedef
NTSTATUS (NTAPI *t_NtQueryInformationProcess)(
    __in       HANDLE ProcessHandle,
    __in       ULONG ProcessInformationClass,
    __out      PVOID ProcessInformation,
    __in       ULONG ProcessInformationLength,
    __out_opt  PULONG ReturnLength
    );

BOOL 
IsWindowsVistaOrLater (
    VOID
    );

STATUS 
EnableSEHOP (
    VOID
    );

STATUS
EnableNativeSEHOP (
    VOID
    );

STATUS
EnablePwnyPotSEHOP (
    VOID
    );

STATUS
VerifyExceptionChain (
    VOID
    );

unsigned int 
GetByte(
    LPVOID address, 
    int byte
    );

struct EXCEPTION_REGISTRATION
{
   EXCEPTION_REGISTRATION *prev;
   DWORD handler;
};

extern "C" {
    void ValidateExceptionChain(void);
}   