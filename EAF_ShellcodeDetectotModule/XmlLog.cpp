#include "XmlLog.h"

PXMLNODE
NewXmlRoot(
	IN CONST PCHAR Name
	)
{
	return ( mxmlNewXML(Name) );
}

PXMLNODE
CreateXmlElement(
	IN PXMLNODE ParentXmlNode,
	IN CONST PCHAR Name
	)
{
	return (mxmlNewElement( ParentXmlNode, Name ) );
}

PXMLNODE
SetTextNode(
	IN PXMLNODE ParentXmlNode,
	IN DWORD WhiteSpace,
	IN CONST PCHAR Value
	)
{
	return ( mxmlNewText( ParentXmlNode, WhiteSpace, Value) );
}

STATUS
SaveXml(
	IN PXMLNODE TopElement
	)
{
	FILE *fp;
	ERRORINFO err;
	CHAR szLogDir[MAX_PATH];
	CHAR szPid[MAX_PATH];

	strncpy(szLogDir, MCEDP_REGCONFIG.LOG_PATH, MAX_PATH);
	strncat(szLogDir, "\\", MAX_PATH);
	sprintf(szPid, "%u_", GetCurrentProcessId(),MAX_PATH);
	strncat(szLogDir, szPid, MAX_PATH);
	strncat(szLogDir, "ShellcodeAnalysis.xml" , MAX_PATH);

    fp = fopen(szLogDir, "w");

	if ( fp == NULL )
	{
		REPORT_ERROR("fopen()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}

    if ( mxmlSaveFile(TopElement, fp, MXML_NO_CALLBACK) == -1 )
	{
		REPORT_ERROR("mxmlSaveFile()", &err);
		return MCEDP_STATUS_INTERNAL_ERROR;
	}
	fflush(fp);
    fclose(fp);
#ifndef CUCKOO    
    if ( TransmitFile(MCEDP_REGCONFIG.LOG_PATH, "ShellcodeAnalysis.xml", "logs/") != MCEDP_STATUS_SUCCESS ) 
    	LOCAL_DEBUG_PRINTF ( "Error on transmission of file ShellcodeAnalysis.xml\n" );
    else 
    	LOCAL_DEBUG_PRINTF ( "Successfully transmitted ShellcodeAnalysis.xml\n" );

#endif 

	return MCEDP_STATUS_SUCCESS;
}
