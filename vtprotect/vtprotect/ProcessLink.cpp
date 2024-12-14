#include "ProcessLink.h"
struct EPROCESSLINK
{
	PEPROCESS process;
	EPROCESSLINK* next;
};
struct PIDLINK
{
	HANDLE pid;
	PIDLINK* next;
};
EPROCESSLINK* protect_eprocess = NULL;
PIDLINK* protect_pid = NULL;
bool IsProtect(PEPROCESS process)
{
	EPROCESSLINK* link = (EPROCESSLINK*)protect_eprocess;
	while (link)
	{
		if (link->process == process)return TRUE;
		link = link->next;
	}
	return FALSE;
}
bool IsProtect(HANDLE pid)
{
	PIDLINK* link = (PIDLINK*)protect_pid;
	while (link)
	{
		if (link->pid == pid)return TRUE;
		link = link->next;
	}
	return FALSE;
}
void AddLink(PEPROCESS process, HANDLE pid)
{
	if (IsProtect(process) || IsProtect(pid))return;
	if (protect_eprocess == NULL)
	{
		protect_eprocess = (EPROCESSLINK*)ExAllocatePool(NonPagedPool, sizeof(EPROCESSLINK));
		protect_eprocess->process = process;
		protect_eprocess->next = NULL;
	}
	else
	{
		EPROCESSLINK* link = (EPROCESSLINK*)protect_eprocess;
		while (link->next != NULL)
		{
			link = link->next;
		}
		link->next = (EPROCESSLINK*)ExAllocatePool(NonPagedPool, sizeof(EPROCESSLINK));
		link->next->process = process;
		link->next->next = NULL;
	}
	if (protect_pid == NULL)
	{
		protect_pid = (PIDLINK*)ExAllocatePool(NonPagedPool, sizeof(PIDLINK));
		protect_pid->pid = pid;
		protect_pid->next = NULL;
	}
	else
	{
		PIDLINK* link = (PIDLINK*)protect_pid;
		while (link->next != NULL)
		{
			link = link->next;
		}
		link->next = (PIDLINK*)ExAllocatePool(NonPagedPool, sizeof(PIDLINK));
		link->next->pid = pid;
		link->next->next = NULL;
	}
}
void DeleteLink()
{
	EPROCESSLINK* process = (EPROCESSLINK*)protect_eprocess;
	while (process!=NULL)
	{
		EPROCESSLINK* link;
		link = process;
		process = process->next;
		ExFreePool(link);
	}
	PIDLINK* pid = (PIDLINK*)protect_pid;
	while (pid!=NULL)
	{
		PIDLINK* link;
		link = pid;
		pid = pid->next;
		ExFreePool(link);
	}
}