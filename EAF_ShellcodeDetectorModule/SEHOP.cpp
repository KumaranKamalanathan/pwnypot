#include "SEHOP.h"

STATUS 
EnableSEHOP(
    VOID
    )
{
    BOOL bIsVista = IsWindowsVistaOrLater();
    /* if below Vista, enable PwnyPot SEHOP */
    if (bIsVista) 
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

extern "C" {    
    unsigned int JmpBackAddress;
}

STATUS
EnablePwnyPotSEHOP (
    VOID
    )
{
    const int patch_length = 8;
    char patch_str [patch_length*2+1];
    /* Get Address of KiUserExceptionDispatcher inside NTDLL.DLL */
    PVOID KiUserExceptionDispatcher = GetProcAddress(GetModuleHandle("NTDLL.DLL"), "KiUserExceptionDispatcher");
    /* read first n bytes in order to verify the version of ntdll and overwrite correctly, 0xfc is left out if XP version */
    unsigned char verification_bytes[] = {0xfc, 0x8b, 0x4c, 0x24, 0x04, 0x8b, 0x1c, 0x24}; 
    /* PATCH: mov eax, function_address ;jmp EAX NOP */ 
    const SIZE_T bytes_to_read = sizeof(verification_bytes)/sizeof(unsigned char);
    unsigned char bytes [bytes_to_read];
    SIZE_T bytes_read;
    BOOL bValid = FALSE;
    BOOL bIsXP = FALSE;

    /* Read bytes from start of KiUserExceptionDispatcher */
    ReadProcessMemory(GetCurrentProcess(), KiUserExceptionDispatcher, (LPVOID)bytes, bytes_to_read, &bytes_read);
    
    /* Windows 7 and XP NTDLL Version 
     * Both Versions differ only in 1st byte of KiUserExceptionDispatcher, therefore we have 
     * to add a NOP instr. for Win 7 Version at the end of our overwrite code
     */
    if (bytes[0] == 0xfc || bytes[0] == 0x8b) 
    {
        /* Windows XP NTDLL Version */
        if (bytes[0] == 0x8b)
            bIsXP = TRUE;
        
        /* Verify correct / known ntdll version */
        /* CLD can be left out if XP version */
        int i = (int) bIsXP;
        int j=0;
        while(verification_bytes[i] == bytes[j]){
            if(j == bytes_read-1) {
                bValid = TRUE;
                break;
            }
            i++;
            j++;
        }   
    }
    else 
    {
        DEBUG_PRINTF(LDBG, NULL, "Check NTDLL Version: Unknown DLL Version.");
        return PWNYPOT_STATUS_GENERAL_FAIL;
    }

    if (bValid) 
    {           
        /* convert char array to unsigned char */
        SIZE_T bytes_written;
        unsigned char patch[patch_length];      
        sprintf_s(patch_str, patch_length*2+1,"b8%02x%02x%02x%02xffe090", GetByte(ValidateExceptionChain, 0), GetByte(ValidateExceptionChain, 1), GetByte(ValidateExceptionChain, 2), GetByte(ValidateExceptionChain, 3));
        for (int i = 0; i < patch_length; i++)
        {
                sscanf_s(&patch_str[i * 2], "%2hhx", &patch[i]);
        }

        /* Overwrite KiUserExceptionDispatcher Prologue with out jmp into checker */
        SIZE_T bytes_to_write = sizeof(patch)/sizeof(unsigned char);
        if(bIsXP)
            bytes_to_write-=1;
        WriteProcessMemory(GetCurrentProcess(), KiUserExceptionDispatcher, patch, bytes_to_write, &bytes_written);
        if(bytes_written!=bytes_to_write)
        {
            DEBUG_PRINTF(LDBG, NULL, "Dispatcher Patch: Could only write %d/%d bytes \n",bytes_written,bytes_to_write);
            return PWNYPOT_STATUS_GENERAL_FAIL;
        }

        /* Address in KiUserExceptionDispatcher after overwritten Prologue */
        JmpBackAddress = ((unsigned int)KiUserExceptionDispatcher+8);
        unsigned char bytes2 [bytes_to_read];
        ReadProcessMemory(GetCurrentProcess(), KiUserExceptionDispatcher, (LPVOID)bytes2, bytes_to_read, &bytes_read);
        return PWNYPOT_STATUS_SUCCESS;
    }
    return PWNYPOT_STATUS_GENERAL_FAIL;
}

/* Returns the n-th byte of the pointer address 0 = LSB, 3 = MSB */
unsigned int GetByte(LPVOID address, int byte)
{
    return ((unsigned int)address >> 8*byte) & 0xff;
}