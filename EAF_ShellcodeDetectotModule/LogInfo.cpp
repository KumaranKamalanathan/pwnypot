#include "LogInfo.h"
#include "ParseConfig.h"

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
BOOL bLogPathInitSuccess = FALSE;

#ifdef CUCKOO
SOCKET LogInfoSock=-1;
SOCKET LogRopSock=-1;
#endif


VOID 
REPORT_ERROR( 
	IN PCHAR Function,
	OUT PERRORINFO ErrorInfo
	)
{
	ErrorInfo->dwErrorNum = GetLastError();
    REPORT_ERROR_EX( Function,
		             GetLastError(),
				     ErrorInfo);
}

VOID 
REPORT_ERROR_EX(
	IN PCHAR Function,
	IN DWORD dwErrorNumber,
	OUT PERRORINFO ErrorInfo
	)
{
	BOOL bErrorHandle;
	HMODULE hErrorDllHandle;

	if ( TRUE ) /* Check for EAF_CONFIG.DISABLE_LOGGING */
	{
		ErrorInfo->dwErrorNum = dwErrorNumber;
		bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
									  NULL,
									  ErrorInfo->dwErrorNum,
									  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
									  ErrorInfo->ErrorMsg,
									  256,
									  NULL);
		if ( bErrorHandle == FALSE )
		{
			/* load library and check the error again for network related errors */
			hErrorDllHandle = LoadLibraryEx("netmsg.dll",
											 NULL,
											 DONT_RESOLVE_DLL_REFERENCES);
			if ( hErrorDllHandle != NULL )
			{
				bErrorHandle = FormatMessage( FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
											  NULL,
											  ErrorInfo->dwErrorNum,
											  MAKELANGID(LANG_NEUTRAL,SUBLANG_DEFAULT),
											  ErrorInfo->ErrorMsg,
											  256,
											  NULL);
			}
		}
		if ( bErrorHandle == FALSE )
		{
			strncpy(ErrorInfo->ErrorMsg,"Unknown Error", 256);
		}

		/* allocate memory for completed error message */
		ErrorInfo->CompletErrorMsg = (CHAR *) LocalAlloc( LMEM_ZEROINIT, 512 );
        _snprintf( ErrorInfo->CompletErrorMsg , MAX_ERROR_MSG, "[!] ERROR : %s failed with error %d (%s)\n", Function, ErrorInfo->dwErrorNum, ErrorInfo->ErrorMsg );
		DEBUG_PRINTF(LDBG, NULL, "%s",ErrorInfo->CompletErrorMsg);
        /* This should free by caller */
        LocalFree(ErrorInfo->CompletErrorMsg);
	}
}


STATUS
InitLogPath(
	OUT PCHAR LogPath,
	IN DWORD Size
	)
{
	CHAR szLogPath[MAX_PATH];
	SYSTEMTIME lt;

    if ( bLogPathInitSuccess )
        return MCEDP_STATUS_SUCCESS;

	SecureZeroMemory(szLogPath, MAX_PATH);
	GetLocalTime( &lt);
	/* init log path by time stamp */
	_snprintf( szLogPath, MAX_PATH, "\\%d.%d.%d ,%d-%d-%d-%d", lt.wYear, lt.wMonth, lt.wDay, lt.wHour, lt.wMinute, lt.wSecond, lt.wMilliseconds);
	strncat( LogPath,  szLogPath ,Size );

	if ( FolderExists( LogPath ) )
    {
        bLogPathInitSuccess = TRUE;
		return MCEDP_STATUS_SUCCESS;
    }

	if ( CreateDirectory( LogPath, NULL ) )
    {
        bLogPathInitSuccess = TRUE;
		return MCEDP_STATUS_SUCCESS;
    }

	return MCEDP_STATUS_INTERNAL_ERROR;	
}


BOOL 
FolderExists(
	LPTSTR szFolderName
	)
{   
    return (GetFileAttributes(szFolderName) != INVALID_FILE_ATTRIBUTES) ? TRUE : FALSE;   
}

PCHAR
strtolow(
    PCHAR szString
    )
{
    PCHAR Container;
    Container = szString;

	while(*Container) 
    {
        *Container = tolower(*Container);
		Container++;
	}

	return szString;
}

VOID
HexDumpToFile(
    PBYTE Data, 
    DWORD dwSize, 
    PCHAR szFileName
    ) 
{
   UINT dp, p;
   FILE *fp;
   CHAR szFullLogPath[MAX_PATH];
   CONST CHAR trans[] = "................................ !\"#$%&'()*+,-./0123456789"
                        ":;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklm"
                        "nopqrstuvwxyz{|}~...................................."
                        "....................................................."
                        "........................................";
    
   strncpy( szFullLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH );
   strncat(szFullLogPath, "\\", MAX_PATH);
   strncat(szFullLogPath, szFileName, MAX_PATH);
   strncat(szFullLogPath, ".txt", MAX_PATH);

	fp = fopen(szFullLogPath, "a");
	if ( fp == NULL )
		return; 

    for (dp = 1; dp <= dwSize; dp++)  
    {
        fprintf(fp,"%02x ", Data[dp-1]);
        if ((dp % 8) == 0)
            fprintf(fp," ");
        if ((dp % 16) == 0) 
        {
            fprintf(fp,"| ");
            p = dp;
            for (dp -= 16; dp < p; dp++)
                fprintf(fp,"%c", trans[Data[dp]]);
            fprintf(fp,"\n");
        }
    }

    if ((dwSize % 16) != 0)
    {
        p = dp = 16 - (dwSize % 16);
        for (dp = p; dp > 0; dp--) 
        {
            fprintf(fp,"   ");
            if (((dp % 8) == 0) && (p != 8))
                fprintf(fp," ");
        }
        fprintf(fp," | ");
        for (dp = (dwSize - (16 - p)); dp < dwSize; dp++)
            fprintf(fp,"%c", trans[Data[dp]]);
    }
    fprintf(fp,"\n");
    fflush(fp);
    fclose(fp);
    return;
}


PCHAR
GenRandomStr(
    PCHAR szString, 
    DWORD dwSize
    ) 
{
    DWORD dwSeed;
    CONST CHAR alphanum[] = "0123456789abcdefghijklmnopqrstuvwxyz";

    Sleep(100);
    dwSeed = ((DWORD)&dwSeed >> 8) ^ (GetTickCount() >> 8) ^ GetCurrentThreadId();
    srand(dwSeed);

    for (int i = 0; i < dwSize; ++i)
        szString[i] = alphanum[rand() % (sizeof(alphanum) - 1)];

    szString[dwSize] = 0;
    return szString;
}



#ifndef CUCKOO
VOID 
DEBUG_PRINTF(
    IN DWORD dwType,
    IN DWORD dwTID,
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[1024] = {0};
    CHAR szFullLogPath[MAX_PATH];
    FILE *fp;
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    strncpy( szFullLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH );
#ifdef __DEBUG__
    if ( dwType == LDBG )
    {
        strncpy( szFullLogPath, MCEDP_REGCONFIG.DBG_LOG_PATH, MAX_PATH );
        strncat( szFullLogPath, "\\LogInfo", MAX_PATH);
    }
#else
    if ( dwType == LDBG )
        return;
#endif
    else if ( dwType == LROP ) 
        strncat(szFullLogPath, "\\RopAnalysis", MAX_PATH);

    fflush(stdout);
    fflush(stderr);

    fp = fopen(szFullLogPath, "a");
    if ( fp == NULL )
        return;

    if ( !bLogStart )
    {
        fprintf(fp, "\n=========================================================================================\n");
        bLogStart = TRUE;
    }
    
    fprintf(fp, "%s", Buffer);
    fflush(fp);
    fclose(fp);
    return;
}


#else 

VOID 
DEBUG_PRINTF(
    IN DWORD dwType,
    IN DWORD dwTID,
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[1024] = {0};
    CHAR szFullLogPath[MAX_PATH];
    FILE *fp;
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);

    strncpy( szFullLogPath, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH );
#ifdef __DEBUG__
    if (  dwType == LDBG ){
        if( LogInfoSock != -1) 
            WriteFileSocket( LogInfoSock, Buffer );
        else             
            LOCAL_DEBUG_PRINTF("Could not write to Log Filesocket\n");
    }
#else
    if ( dwType == LDBG )
        return;
#endif
    else if ( dwType == LROP )
    {
        if ( LogRopSock != -1 ){
            WriteFileSocket( LogRopSock, Buffer );
        }
        else 
        {
            LOCAL_DEBUG_PRINTF("Could not write to ROP Filesocket\n");
        }
    }
    return;
}


VOID LOCAL_DEBUG_PRINTF (
    IN PCHAR Format, 
    IN ...
    )
{
    CHAR Buffer[1024] = {0};
    CHAR szFullLogPath[MAX_PATH];
    CHAR szPid [MAX_PATH];
    FILE *fp;
    va_list Args;

    va_start(Args, Format);
    vsnprintf_s(Buffer, sizeof Buffer, _TRUNCATE, Format, Args);
    va_end(Args);
    strncpy( szFullLogPath, MCEDP_REGCONFIG.DBG_LOG_PATH, MAX_PATH );
    strncat( szFullLogPath, "\\LogInfo_", MAX_PATH);
    sprintf(szPid, "%u", GetCurrentProcessId(), MAX_PATH);
    strncat( szFullLogPath, szPid, MAX_PATH);
    strncat( szFullLogPath, ".txt", MAX_PATH);

    fflush(stdout);
    fflush(stderr);

    fp = fopen(szFullLogPath, "a");
    if ( fp == NULL )
        return;
    
    fprintf(fp, "%s", Buffer);
    fflush(fp);
    fclose(fp);
    return;
}

SOCKET 
InitFileSocket (
    PCHAR szFileName
    )
{
    SOCKET s;
    WSADATA wsadata;
    CHAR szPid[MAX_PATH];
    sprintf(szPid, "%u", GetCurrentProcessId(), MAX_PATH);

    LOCAL_DEBUG_PRINTF("Initializing File Socket\n");
    int error = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (error)
    {
        LOCAL_DEBUG_PRINTF("WSAStartup error\n");
        return -1;
    }

    if (wsadata.wVersion != MAKEWORD(2, 2))
    {
        LOCAL_DEBUG_PRINTF("Wrong version\n");
        return -1;
    }

    SOCKADDR_IN target; 

    target.sin_family = AF_INET; 
    target.sin_addr.s_addr = inet_addr (MCEDP_REGCONFIG.RESULT_SERVER_IP); 
    target.sin_port = htons (MCEDP_REGCONFIG.RESULT_SERVER_PORT); 
    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (s == INVALID_SOCKET)
    {
        LOCAL_DEBUG_PRINTF("Invalid Socket\n");
        return -1; 
    }  

    if (connect(s, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR)
    {
        LOCAL_DEBUG_PRINTF("Socket Error\n");
        return -1; 
    }
    else
    {
        const int LENGTH = 512;

        char buffer[256];
        int n;

        memset(buffer, '\0', 256);
        strncpy(buffer, "FILE\nlogs/",256);
        strncat(buffer, szPid, 256);
        strncat(buffer, "_", 256);
        strncat(buffer, szFileName,256);
        strncat(buffer, "\n",256);
        n = send(s,buffer, strlen(buffer),0);   

        LOCAL_DEBUG_PRINTF("Successfully Initialized FileSocket\n");
    }
    return s;
}

STATUS 
WriteFileSocket (
    SOCKET Socket,
    PCHAR Buffer
    )
{   
    LOCAL_DEBUG_PRINTF("WriteFileSocket called on Socket %d\n", Socket );
    int res = send ( Socket, Buffer, strlen( Buffer ), 0 );
    LOCAL_DEBUG_PRINTF("Sent %d bytes: %s\n", res, Buffer);
    if ( res == SOCKET_ERROR ) {
        LOCAL_DEBUG_PRINTF("Last error: %d\n", WSAGetLastError());
    }
    return MCEDP_STATUS_SUCCESS;
}

STATUS 
InitCuckooLogs ()
{
    LOCAL_DEBUG_PRINTF("Initializing Cuckoo Socket Logs from PID: %u\n",GetCurrentProcessId());
    if ( bLogPathInitSuccess )
        return MCEDP_STATUS_SUCCESS;
    // init LogInfo.txt
    LogInfoSock = InitFileSocket("LogInfo.txt");
    if (LogInfoSock==-1){
        return MCEDP_STATUS_INTERNAL_ERROR;
    }

    // init RopDetection.txt
    LogRopSock = InitFileSocket("RopAnalysis.txt");
    if (LogRopSock==-1){
        return MCEDP_STATUS_INTERNAL_ERROR;
    }

    bLogPathInitSuccess = TRUE;
    return MCEDP_STATUS_SUCCESS;
}

STATUS
CloseCuckooLogs ()
{
    closesocket(LogInfoSock);
}


STATUS 
TransmitFile (
    PCHAR szLocalPath,
	PCHAR szFileName,
    PCHAR szRemotePath
	)
{
	SOCKET s;
    WSADATA wsadata;
	CHAR szFullPath[MAX_PATH];
	
    int error = WSAStartup(MAKEWORD(2, 2), &wsadata);
    if (error)
    {
        return MCEDP_STATUS_INTERNAL_ERROR;
    }

    if (wsadata.wVersion != MAKEWORD(2, 2))
    {
        WSACleanup(); //Clean up Winsock
        return MCEDP_STATUS_INTERNAL_ERROR;
    }

    SOCKADDR_IN target; 

    target.sin_family = AF_INET; 
    target.sin_addr.s_addr = inet_addr (MCEDP_REGCONFIG.RESULT_SERVER_IP); 
    target.sin_port = htons (MCEDP_REGCONFIG.RESULT_SERVER_PORT); 
    s = socket (AF_INET, SOCK_STREAM, IPPROTO_TCP); 
    if (s == INVALID_SOCKET)
    {
        DEBUG_PRINTF(LDBG, NULL, "ERROR: Invalid socket for file transmission.\n");
        return MCEDP_STATUS_INTERNAL_ERROR; 
    }  

    if (connect(s, (SOCKADDR *)&target, sizeof(target)) == SOCKET_ERROR)
    {
        DEBUG_PRINTF(LDBG, NULL, "ERROR: Failed to connect to socket for file transmission.\n");
        return MCEDP_STATUS_INTERNAL_ERROR; 
    }
    else
    {
        const int LENGTH = 512;
        char sdbuf[LENGTH]; 
        char buffer[LENGTH];
        int n;

        memset(buffer, '\0', LENGTH);
        strncpy(buffer, "FILE\n",LENGTH);
        strncat(buffer, szRemotePath,LENGTH);
        strncat(buffer, szFileName,LENGTH);
        strncat(buffer, "\n",LENGTH);
        n = send(s,buffer, strlen(buffer),0);    

        strncpy(szFullPath, szLocalPath,MAX_PATH);
        strncat(szFullPath, "\\",LENGTH);
        strncat(szFullPath, szFileName,MAX_PATH);

        FILE *fs = fopen(szFullPath, "r");
        if(fs == NULL)
        {
            DEBUG_PRINTF(LDBG, NULL, "ERROR: Failed to open file for sending %s. (errno = %d)\n", szFullPath, errno);
            return MCEDP_STATUS_INTERNAL_ERROR;
        }

        memset(sdbuf, '\0', LENGTH); 
        int fs_block_sz;
        while((fs_block_sz = fread(sdbuf, sizeof(char), LENGTH, fs)) > 0)
        {
            if(send(s, sdbuf, fs_block_sz, 0) < 0)
            {
                DEBUG_PRINTF(LDBG, NULL, "ERROR: Failed to send file %s. (errno = %d)\n", szFullPath, errno);
                return MCEDP_STATUS_INTERNAL_ERROR;
            }
            memset(sdbuf, '\0', LENGTH);
        }
        closesocket(s);

        return MCEDP_STATUS_SUCCESS; 	
    }
}

#endif
