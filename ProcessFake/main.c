#include <ntifs.h>
#include "ProcessFake.h"

VOID DriverUnload(PDRIVER_OBJECT pDriver)
{
	DbgPrintEx(77, 0, "DriverUnload\r\n");
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING pReg)
{
	PEPROCESS fakeProcess = NULL;
	PsLookupProcessByProcessId((HANDLE)6992, &fakeProcess);
	
	FakeProcessByPid(fakeProcess, 412);

	pDriver->DriverUnload = DriverUnload;
	return STATUS_SUCCESS;
}