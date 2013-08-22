#include <Windows.h>
#include <stdlib.h>
#include "ParseConfig.h"
#include "LogInfo.h"
#include "Hook.h"
#pragma once

#define ProcessExecuteFlags				0x22
#define MEM_EXECUTE_OPTION_DISABLE		0x01
#define MEM_EXECUTE_OPTION_ENABLE		0x02
#define MEM_EXECUTE_OPTION_PERMANENT	0x08
#define NT_SUCCESS(Status)				(((NTSTATUS)(Status)) >= 0)

extern PWNYPOTREGCONFIG PWNYPOT_REGCONFIG;

typedef
NTSTATUS
(NTAPI *NtAllocateVirtualMemory_)(
	__in     HANDLE ProcessHandle,
	__inout  PVOID *BaseAddress,
	__in     ULONG_PTR ZeroBits,
	__inout  PSIZE_T RegionSize,
	__in     ULONG AllocationType,
	__in     ULONG Protect
);

STATUS
EnablePermanentDep(
	VOID
	);


STATUS
EnableNullPageProtection(
	VOID
	);

STATUS
EnableHeapSprayProtection(
	IN PCHAR szHeapAddressArray
	);