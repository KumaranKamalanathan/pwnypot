#include "CuckooPipe.h"

int pipe(PCHAR buf)
{    
    DWORD len = strlen(buf);
    return CallNamedPipe(MCEDP_REGCONFIG.CUCKOO_PIPE_NAME, buf, len, buf, len,(unsigned long *) &len, NMPWAIT_WAIT_FOREVER);
}
