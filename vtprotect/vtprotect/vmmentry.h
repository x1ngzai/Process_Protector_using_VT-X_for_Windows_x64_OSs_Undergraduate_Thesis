#pragma once
#include "stdafx.h" 
typedef struct _GUEST_REGS
{
	ULONG64 RFLAGS;
	ULONG64 rax;
	ULONG64 rbx;
	ULONG64 rcx;
	ULONG64 rdx;
	ULONG64 rsi;
	ULONG64 rdi;
	ULONG64 rbp;
	ULONG64 r8;
	ULONG64 r9;
	ULONG64 r10;
	ULONG64 r11;
	ULONG64 r12;
	ULONG64 r13;
	ULONG64 r14;
	ULONG64 r15;
	ULONG64 cr3;
	ULONG64 rip;
	ULONG64 rsp;
}GUEST_REGS, *PGUEST_REGS;