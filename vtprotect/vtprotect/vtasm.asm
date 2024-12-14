EXTERN FucList:DQ
EXTERN SYS_CALL64:DQ
VMMEntryPoint Proto
SetupVMCS Proto
.code

sys_fuc Proc
	cli
	swapgs
	mov gs:[10h],rsp
	mov rsp,gs:[1a8h]
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rbp
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push rax
	pushfq
	;;;;;;;;;;;;;
	cmp rax,500
	jnl nor
	shl rax,3
	lea rbx,[FucList]
	add rbx,rax
	cmp qword ptr[rbx],0
	je nor
	mov rbx,[rbx]
	mov rdx,gs:[10h]
	mov rax,rsp
	;;;;;;;;;;;;;
	sub rsp,8*12
	;;;;;;;;;;;;;
	lea rcx,[rdx+8*5]
	mov [rsp+8*4],rcx
	lea rcx,[rdx+8*6]
	mov [rsp+8*5],rcx
	lea rcx,[rdx+8*7]
	mov [rsp+8*6],rcx
	lea rcx,[rdx+8*8]
	mov [rsp+8*7],rcx
	lea rcx,[rdx+8*9]
	mov [rsp+8*8],rcx
	lea rcx,[rdx+8*10]
	mov [rsp+8*9],rcx
	lea rcx,[rdx+8*11]
	mov [rsp+8*10],rcx
	lea rcx,[rdx+8*12]
	mov [rsp+8*11],rcx
	lea rcx,[rax+8*10]
	lea rdx,[rax+8*4]
	lea r8,[rax+8*8]
	lea r9,[rax+8*9]
    call rbx

	add rsp,8*12
	;;;;;;;;;;;;
	
	;;;;;;;;;;;;;;
	nor:    popfq
		pop rax
		pop rbx
		pop rcx
		pop rdx
		pop rsi
		pop rdi
		pop rbp 
		pop r8
		pop r9
		pop r10
		pop r11
		pop r12
	pop r13
	pop r14
	pop r15
		mov rsp,gs:[10h]
		swapgs
		jmp [SYS_CALL64]
sys_fuc Endp

_CPUID Proc
 push	rbp
	mov		rbp, rsp
	push	rbx
	push	rsi

	mov		[rbp+18h], rdx
	mov		eax, ecx
	cpuid
	mov		rsi, [rbp+18h]
	mov		[rsi], eax
	mov		[r8], ebx
	mov		[r9], ecx
	mov		rsi, [rbp+30h]
	mov		[rsi], edx	

	pop		rsi
	pop		rbx
	mov		rsp, rbp
	pop		rbp
	ret
_CPUID Endp


_Rdtsc Proc
	mov rbx,rcx
	mov rsi,rdx

	xor rax,rax
	xor rdx,rdx

	rdtsc
	mov [rbx],rax
	mov [rsi],rdx
	ret
_Rdtsc Endp


_Invd Proc
	invd
	ret
_Invd Endp



ReadMsr		Proc
	xor rax,rax
	xor rdx,rdx
	
	rdmsr
	shl rdx,32
	or rax,rdx
	ret
ReadMsr		Endp

WriteMsr	Proc
	xor rax,rax
	
	mov	eax,edx
	shr rdx,32
	wrmsr
	ret
WriteMsr 	Endp


GetCs PROC
	mov		rax, cs
	ret
GetCs ENDP

GetDs PROC
	mov		rax, ds
	ret
GetDs ENDP

GetEs PROC
	mov		rax, es
	ret
GetEs ENDP

GetSs PROC
	mov		rax, ss
	ret
GetSs ENDP

GetFs PROC
	mov		rax, fs
	ret
GetFs ENDP

GetGs PROC
	mov		rax, gs
	ret
GetGs ENDP


GetCr0		Proc
	mov 	rax, cr0
	ret
GetCr0 		Endp

GetCr3		Proc
	
	mov 	rax, cr3
	ret
GetCr3 		Endp

GetCr4		Proc
	mov 	rax, cr4
	ret
GetCr4 		Endp

SetCr0		Proc
	mov	cr0, rcx
	ret
SetCr0 		Endp

SetCr2		Proc
	mov	cr2, rcx
	ret
SetCr2 		Endp

SetCr3		Proc
	mov	cr3, rcx
	ret
SetCr3 		Endp

SetCr4		Proc
	mov cr4, rcx
	ret
SetCr4 		Endp

GetDr0 PROC
	mov		rax, dr0
	ret
GetDr0 ENDP

GetDr1 PROC
	mov		rax, dr1
	ret
GetDr1 ENDP

GetDr2 PROC
	mov		rax, dr2
	ret
GetDr2 ENDP

GetDr3 PROC
	mov		rax, dr3
	ret
GetDr3 ENDP

GetDr6 PROC
	mov		rax, dr6
	ret
GetDr6 ENDP

GetDr7 PROC
	mov		rax, dr7
	ret
GetDr7 ENDP

SetDr0 PROC
	mov		dr0, rcx
	ret
SetDr0 ENDP

SetDr1 PROC
	mov		dr1, rcx
	ret
SetDr1 ENDP

SetDr2 PROC
	mov		dr2, rcx
	ret
SetDr2 ENDP

SetDr3 PROC
	mov		dr3, rcx
	ret
SetDr3 ENDP

SetDr6 PROC
	mov		dr6, rcx
	ret
SetDr6 ENDP

SetDr7 PROC
	mov		dr7, rcx
	ret
SetDr7 ENDP

GetRflags PROC
	pushfq
	pop		rax
	ret
GetRflags ENDP

GetIdtBase PROC
	LOCAL	idtr[10]:BYTE
	
	sidt	idtr
	mov		rax, qword PTR idtr[2]
	ret
GetIdtBase ENDP

GetIdtLimit PROC
	LOCAL	idtr[10]:BYTE
	
	xor rax,rax
	sidt	idtr
	mov		ax, WORD PTR idtr[0]
	ret
GetIdtLimit ENDP

GetGdtBase PROC
	LOCAL	gdtr[10]:BYTE

	sgdt	gdtr
	mov		rax, qword PTR gdtr[2]
	ret
GetGdtBase ENDP

GetGdtLimit PROC
	LOCAL	gdtr[10]:BYTE
	
	xor rax,rax
	sgdt	gdtr
	mov		ax, WORD PTR gdtr[0]
	ret
GetGdtLimit ENDP

GetLdtr PROC
	sldt	rax
	ret
GetLdtr ENDP

GetTr PROC
	str	rax
	ret
GetTr ENDP

SetGdtr		Proc
	push	rcx
	shl	rdx, 16
	push	rdx
	
	lgdt	fword ptr [rsp+2]
	pop	rax
	pop	rax
	ret
SetGdtr	Endp

SetIdtr		Proc
	push	rcx
	shl	rdx, 16
	push	rdx
	lidt	fword ptr [rsp+2]
	pop	rax
	pop	rax
	ret
SetIdtr	Endp



GetTSC PROC
	rdtsc
	shl		rdx, 32
	or		rax, rdx
	ret
GetTSC ENDP


Vmx_VmxOn Proc
	push rcx
	Vmxon qword ptr [rsp]
	add rsp,8
	ret
Vmx_VmxOn Endp

Vmx_VmxOff Proc
	Vmxoff
	ret
Vmx_VmxOff Endp

Vmx_VmPtrld Proc
	push rcx
	vmptrld qword ptr [rsp]
	add rsp,8
	ret
Vmx_VmPtrld endp

Vmx_VmClear Proc
	push rcx
	vmclear qword ptr [rsp]
	add rsp,8
	ret
Vmx_VmClear endp

Vmx_VmRead Proc
	mov rax,rcx
	vmread rcx,rax
	mov rax,rcx
	ret
Vmx_VmRead endp

Vmx_VmWrite Proc
	mov rax,rcx
	mov rcx,rdx
	vmwrite rax,rcx
	ret
Vmx_VmWrite endp

; CmInvept (PVOID Ep4ta(rcx), ULONG inval (rdx) );
Vmx_Invept proc
     push	 rbp
	 mov	 rbp, rsp
	 push    rsi
	 mov     rsi, rcx
	 mov     rax, rdx
	 invept  rax, xmmword ptr [rsi]
	 pop     rsi
	 mov	 rsp, rbp
	 pop	 rbp
	 ret
Vmx_Invept endp

Vmx_VmCall Proc
	mov rax,rcx
	vmcall
	ret
Vmx_VmCall endp

Vmx_VmLaunch Proc
	vmlaunch
	ret
Vmx_VmLaunch endp

Vmx_VmResume Proc
	vmresume
	ret
Vmx_VmResume endp



VMMEntryPoint_fuc Proc
         cli
		;int 3
		sub rsp,8   ;push rsp
		sub rsp,8  ;push rip
	sub rsp,8  ;push cr3
	push r15
	push r14
	push r13
	push r12
	push r11
	push r10
	push r9
	push r8
	push rbp
	push rdi
	push rsi
	push rdx
	push rcx
	push rbx
	push rax
	pushfq
		;;;;;;;;;;;;;;;
		mov rcx, rsp
		sub rsp,8
		call VMMEntryPoint
		add rsp,8
		;;;;;;;;;;;;
		cmp rax,0
		jne vtoff
		;;;;;;;;;;;;;;;;;
		popfq
		pop rax
		pop rbx
		pop rcx
		pop rdx
		pop rsi
		pop rdi
		pop rbp 
		pop r8
		pop r9
		pop r10
		pop r11
		pop r12
	pop r13
	pop r14
	pop r15
	add rsp,8   ;pop cr3
	add rsp,8   ;pop rip
	add rsp,8   ;pop rsp
		sti
		vmresume

vtoff:		
			popfq
		pop rax
		pop rbx
		pop rcx
		pop rdx
		pop rsi
		pop rdi
		pop rbp 
		pop r8
		pop r9
		pop r10
		pop r11
		pop r12
	pop r13
	pop r14
	pop r15
	add rsp,8   ;pop cr3
	mov rax,[rsp]
	add rsp,8   ;pop rip
    mov rsp,[rsp]
		sti
		jmp rax
VMMEntryPoint_fuc Endp

SetupVMCS_fuc Proc
sub rsp,10h
mov rcx,rsp
mov rdx,vmlunch_ret
call SetupVMCS
vmlunch_ret:add rsp,10h
ret
SetupVMCS_fuc Endp
END