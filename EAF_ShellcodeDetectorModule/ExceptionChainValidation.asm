.386
.model flat, c
option casemap :none

printf proto c :vararg 

extern JmpBackAddress:dword

.data
msg BYTE "Checker function has been called!",0 

.code
ValidateExceptionChain proc 
	;push offset msg
	;call printf
	;add esp,4
	
	assume fs:nothing			; To ignore MASM warning of using fs register
	mov eax,fs:[0]
	mov ecx,-1					; End of Chain has 0xffffffff as next field
	cmp [eax],ecx			
	jz DispatcherPrologue		; There is no next Exception Registration, jump over WalkChain

WalkChain:
	mov eax,[eax]				; load next field into eax
	cmp eax,ecx					; Check if next field equals 0xffffffff
	jnz WalkChain			

DispatcherPrologue:				;overwritten prologue of KiUserExceptionDispatcher
	CLD
	mov ecx,dword ptr ss:[esp+4]
	mov ebx,dword ptr ss:[esp]

	push JmpBackAddress			; jump back to KiUserExceptionDispatcher after Prologue
	ret
ValidateExceptionChain endp

END
