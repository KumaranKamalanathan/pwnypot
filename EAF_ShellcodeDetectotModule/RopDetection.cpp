#include "RopDetection.h"

BOOL bRopDetected = FALSE;
BOOL bRopLoged = FALSE;

extern "C"
VOID
ValidateCallAgainstRop(
	IN ULONG_PTR lpEspAddress,
	IN ROP_CALLEE RopCallee,
	IN LPVOID lpAddress, 
	IN DWORD flProtect
	)
{
	PNT_TIB ThreadInfo;
	
	if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_NOT_SET )
	{
		/* get the thread stack range from TIB. */
		ThreadInfo = (PNT_TIB) __readfsdword( 0x18 );

		/* monitor esp value if we supposed to */
		if ( MCEDP_REGCONFIG.ROP.STACK_MONITOR )
		{
			/* check if thread is passing the actual stack boundaries */
			if ( lpEspAddress < (DWORD)ThreadInfo->StackLimit || lpEspAddress >= (DWORD)ThreadInfo->StackBase ) 
			{
				/* set ROP flags */
				DbgSetRopFlag();
				DEBUG_PRINTF(LROP,NULL,"ROP Detected by STACK_MONITOR, out of bound stack!\n");
			}
		}

		/* Monitor stack page permission change value if we supposed to */
		if ( MCEDP_REGCONFIG.MEM.STACK_RWX )
		{
			if ( lpAddress > ThreadInfo->StackLimit || lpAddress <= ThreadInfo->StackBase )
			{
				/* if it is going to make the stack executable */
				if ( ( flProtect & PAGE_EXECUTE )           ||  
					 ( flProtect & PAGE_EXECUTE_READWRITE ) || 
					 ( flProtect & PAGE_EXECUTE_READ )      ||
					 ( flProtect & PAGE_EXECUTE_WRITECOPY ) )
				{
					/* set ROP flag */
					DbgSetRopFlag();
					DEBUG_PRINTF(LROP,NULL,"ROP Detected by STACK_RWX, stack permission changed to be executable!\n");
				}
			}
		}

		if ( MCEDP_REGCONFIG.ROP.PIVOT_DETECTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( MCEDP_REGCONFIG.ROP.CALL_VALIDATION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( MCEDP_REGCONFIG.ROP.FORWARD_EXECUTION )
		{
			/* NOT IMPLEMENTED */
		}

		if ( DbgGetRopFlag() == MCEDP_STATUS_ROP_FLAG_SET )
		{
			if ( MCEDP_REGCONFIG.ROP.DUMP_ROP )
			{
				DEBUG_PRINTF(LROP, NULL, "Trying to dump ROP from ESP at 0x%p and APINumber %d\n",(PVOID)lpEspAddress, RopCallee);
				DbgReportRop((PVOID)lpEspAddress,RopCallee);
			}

			if ( MCEDP_REGCONFIG.ROP.KILL_ROP)
				TerminateProcess(GetCurrentProcess(), STATUS_ACCESS_VIOLATION);
		}
	}
}



STATUS
DbgSetRopFlag(
	VOID
	)
{

	/* set the ROP flag */
	bRopDetected = TRUE;

    /* init log path */
#ifndef CUCKOO
    if ( InitLogPath( MCEDP_REGCONFIG.LOG_PATH, MAX_PATH ) != MCEDP_STATUS_SUCCESS )
	{
    	ERRORINFO err;
		REPORT_ERROR("InitLogPath()", &err);
		return MCEDP_STATUS_GENERAL_FAIL;
	}
#endif

	return MCEDP_STATUS_SHELLCODE_FLAG_SET;
}

STATUS
DbgGetRopFlag(
	VOID
	)
{
	/* get current value of ROP flag */
	if ( bRopDetected )
		return MCEDP_STATUS_ROP_FLAG_SET;

	return MCEDP_STATUS_ROP_FLAG_NOT_SET;
}

STATUS
DbgGetRopModule(
	IN PVOID StackPointerAddress,
	OUT PCHAR ModuleFullName,
	IN DWORD dwSize
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	DWORD ModuleCount = 0;

    /* translate StackPointerAddress to module name */
	if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)StackPointerAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
	{
		wcstombs( ModuleFullName, TableEntry->FullDllName.Buffer, dwSize );
		return MCEDP_STATUS_SUCCESS;
	} 

	return MCEDP_STATUS_INTERNAL_ERROR;
}

VOID
DbgReportRop(
	IN CONST PVOID Address,
	IN CONST DWORD APINumber
	)
{
	PLDR_DATA_TABLE_ENTRY TableEntry;
	LPVOID lpAddress;
	LPVOID lpCodeSectionAddress;
	CHAR szAssciFullModuleName[MAX_MODULE_NAME32];
	CHAR szAssciModuleName[MAX_MODULE_NAME32];
	PCHAR szRopInst;
	CHAR szTemp[1024];
	DWORD dwCodeSectionSize;
	DWORD i;
	PXMLNODE XmlLogNode;
	PXMLNODE XmlIDLogNode;;
	PXMLNODE XmlSubNode;

	XmlIDLogNode = CreateXmlElement( XmlShellcode, "row");
    // type
    mxmlElementSetAttr(XmlIDLogNode, "type", "0");

    // data
	SecureZeroMemory(szAssciFullModuleName, MAX_MODULE_NAME32);
	SecureZeroMemory(szAssciModuleName, MAX_MODULE_NAME32);
	szRopInst = (PCHAR)LocalAlloc(LMEM_ZEROINIT, 2048);
	lpAddress = Address;
	bRopDetected = TRUE;

    /* Get function name which reports rop */
	switch (APINumber)
	{
	case CalleeVirtualAlloc:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualAlloc");
		break;
	case CalleeVirtualAllocEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualAllocEx");
		break;
	case CalleeVirtualProtect:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualProtect");
		break;
	case CalleeVirtualProtectEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "VirtualProtectEx");
		break;
	case CalleeMapViewOfFile:
		mxmlElementSetAttr( XmlIDLogNode, "function", "MapViewOfFile");
		break;
	case CalleeMapViewOfFileEx:
		mxmlElementSetAttr( XmlIDLogNode, "function", "MapViewOfFileEx");
		break;
	}

    /* Get the module that used for rop gadgets */
	if ( DbgGetRopModule( lpAddress, szAssciFullModuleName, MAX_MODULE_NAME32) == MCEDP_STATUS_SUCCESS )
	{
		DEBUG_PRINTF(LROP, NULL, "Rop Module name: %s\n", szAssciFullModuleName);
		mxmlElementSetAttr( XmlIDLogNode, "module", szAssciFullModuleName);
	}

    /* Dump possible ROP gadgets */
	if ( MCEDP_REGCONFIG.ROP.DUMP_ROP == TRUE )
	{
		lpAddress = (PVOID)((DWORD_PTR)lpAddress - MCEDP_REGCONFIG.ROP.ROP_MEM_FAR);
		for ( i = 0 ; i <= MCEDP_REGCONFIG.ROP.MAX_ROP_MEM ; i++ , lpAddress = (LPVOID)((DWORD)lpAddress + 4) )
		{

			XmlLogNode = CreateXmlElement ( XmlIDLogNode, "rop_gadget");
			if ( LdrFindEntryForAddress((PVOID)(*(DWORD *)lpAddress), &TableEntry) == MCEDP_STATUS_SUCCESS )
			{
				/* get module name */
				wcstombs( szAssciModuleName, TableEntry->FullDllName.Buffer, TableEntry->FullDllName.Length );

				/* Get module .text section start address */
				if ( ( lpCodeSectionAddress = PeGetCodeSectionAddress( TableEntry->DllBase ) ) == NULL )
				{
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "FAILED -- MODULE CODE SECTION ADDRESS NULL");
					DEBUG_PRINTF(LROP, NULL, "FAILED -- MODULE CODE SECTION ADDRESS NULL\n");
					break;
				}

				/* Get module .text section size */
				if ( ( dwCodeSectionSize = PeGetCodeSectionSize( TableEntry->DllBase ) ) == NULL )
				{
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "FAILED -- MODULE CODE SECTION SIZE NULL");
					DEBUG_PRINTF(LROP, NULL, "FAILED -- MODULE CODE SECTION SIZE NULL\n");
					break;
				}

				/* Check if instruction lies inside the .text section */
				if ( (*(ULONG_PTR *)lpAddress) >= (ULONG_PTR)lpCodeSectionAddress && (*(ULONG_PTR *)lpAddress) < ( (ULONG_PTR)lpCodeSectionAddress + dwCodeSectionSize ) )
				{

					if ( ShuDisassmbleRopInstructions( (PVOID)(*(ULONG_PTR *)lpAddress), szRopInst, MCEDP_REGCONFIG.ROP.MAX_ROP_INST ) == MCEDP_STATUS_SUCCESS )
					{
						mxmlElementSetAttrf(XmlLogNode, "offset", "0x%p", (*(ULONG_PTR *)lpAddress - (ULONG_PTR)TableEntry->DllBase));
						DEBUG_PRINTF(LROP, NULL, "found rop_module: \n", szTemp);

						XmlSubNode = mxmlNewElement( XmlLogNode, "rop_inst");
        				memset( szTemp, '\0', 1024 );
						sprintf( szTemp, "%s", szRopInst );	
						mxmlNewText( XmlSubNode, 0, szTemp );	
						DEBUG_PRINTF(LROP, NULL, "found rop_inst: %s \n", szTemp);
					} 
					else
					{
						XmlSubNode = mxmlNewElement( XmlLogNode, "error");
						mxmlNewText( XmlSubNode, 0, "FAILED TO DISASSMBLE");
						DEBUG_PRINTF(LROP, NULL, "FAILED TO DISASSMBLE\n");
					}

					SecureZeroMemory(szRopInst, 2048);

				} else {
					XmlSubNode = mxmlNewElement( XmlLogNode, "error");
					mxmlNewText( XmlSubNode, 0, "OUT OF CODE SECTION");
				}
			}
			else  {
				XmlSubNode = mxmlNewElement( XmlLogNode, "address");
	        	memset( szTemp, '\0', 1024 );
				sprintf( szTemp, "0x%p", lpAddress);
				mxmlNewText ( XmlSubNode, 0, szTemp );

				XmlSubNode = mxmlNewElement( XmlLogNode, "val_at_addr");
	        	memset( szTemp, '\0', 1024 );
				sprintf( szTemp, "0x%p", (*(ULONG_PTR *)lpAddress));
				mxmlNewText ( XmlSubNode, 0, szTemp );
			}
		}
	}

	DEBUG_PRINTF(LROP, NULL, "Trying to save ROP gadget XML File\n");
	SaveXml( XmlLog );
	LocalFree(szRopInst);
}
