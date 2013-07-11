#include "mxml\src\mxml-2.7\mxml.h"
#include "LogInfo.h"
#include "ParseConfig.h"

#define LSC		1
#define LROP 	2

extern MCEDPREGCONFIG MCEDP_REGCONFIG;
typedef mxml_node_t XMLNODE;
typedef mxml_node_t* PXMLNODE;

PXMLNODE
NewXmlRoot(
	IN CONST PCHAR Name
	);

PXMLNODE
CreateXmlElement(
	IN PXMLNODE ParentXmlNode,
	IN CONST PCHAR Name
	);


PXMLNODE
SetTextNode(
	IN PXMLNODE ParentXmlNode,
	IN DWORD WhiteSpace,
	IN CONST PCHAR Value
	);

STATUS
SaveXml(
	IN DWORD dwType,
	IN PXMLNODE TopElement
	);