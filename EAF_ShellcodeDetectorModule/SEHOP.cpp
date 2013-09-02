#include "SEHOP.h"

STATUS 
EnableSEHOP(
    VOID
    )
{
    BOOL bIsVista = IsWindowsVistaOrLater();
    /* if below Vista, enable PwnyPot SEHOP */
    if (!bIsVista) 
    {
        DEBUG_PRINTF(LDBG, NULL, "Trying to enable PwnyPot SEHOP\n");
        return EnablePwnyPotSEHOP();
    }

    /* if Vista or newer, enable Native SEHOP of the Process*/
    else 
    {   
        DEBUG_PRINTF(LDBG, NULL, "Trying to enable native SEHOP\n");
        return EnableNativeSEHOP();
    } 
}

BOOL 
IsWindowsVistaOrLater (
    VOID
    )
{
    OSVERSIONINFO osvi;
    BOOL bIsWindowsXPorLater;

    ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
    osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

    GetVersionEx(&osvi);
    /* Vista is above or equal Version 6 */
    if (osvi.dwMajorVersion >= 6)
    {
        return TRUE;
    }
    else {
        return FALSE;
    }
}

STATUS 
EnableNativeSEHOP (
    VOID
    )
{
    NTSTATUS status;
    ULONG uSize;
    ULONG ExecuteFlags;
    t_NtSetInformationProcess NtSetInformationProcess_ = (t_NtSetInformationProcess)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtSetInformationProcess"));
    t_NtQueryInformationProcess NtQueryInformationProcess_ = (t_NtQueryInformationProcess)(GetProcAddress(GetModuleHandle("NTDLL.DLL"), "NtQueryInformationProcess"));
    if (NtQueryInformationProcess_ != NULL && NtSetInformationProcess_ != NULL )
    {
        status = NtQueryInformationProcess_( GetCurrentProcess(), PROCESS_EXECUTE_FLAG, &ExecuteFlags, sizeof(ExecuteFlags), &uSize );
        if(NT_SUCCESS(status))
        {
            if(!(ExecuteFlags & MEM_EXECUTE_OPTION_PERMANENT))
            {
                ExecuteFlags &= ~(SEHOP_FLAG);
                status = NtSetInformationProcess_( GetCurrentProcess(), PROCESS_EXECUTE_FLAG, &ExecuteFlags, sizeof(ExecuteFlags));
                if ( NT_SUCCESS(status) )
                {
                    return PWNYPOT_STATUS_SUCCESS;
                }
            }
            else {
                return PWNYPOT_STATUS_SUCCESS;
            }
        }
    }
    return PWNYPOT_STATUS_GENERAL_FAIL;
}

STATUS
EnablePwnyPotSEHOP (
    VOID
    )
{
    return PWNYPOT_STATUS_SUCCESS;
}