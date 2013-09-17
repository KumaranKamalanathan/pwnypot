.386
.model flat, c
option casemap :none

_DEBUG_PRINTF proto syscall
_IllegalExceptionHandler proto syscall
extern JmpBackAddress:dword

.data
msg BYTE "Found illegal next field",0ah, 0h
msg2 BYTE "Found illegal handler",0ah, 0h
msgStart BYTE "Starting Chain Validation",0ah, 0h
msgEnd BYTE "Chain Validation completed. No Attack", 0ah, 0h 

.code
ValidateExceptionChain proc 
	assume fs:nothing			; To ignore MASM warning of using fs register

  	push offset msgStart
  	push 0
  	push 2
  	call _DEBUG_PRINTF
  	add esp,12

	mov ecx,fs:[0]				; load address of exception registration into ecx 
	add ecx,4					; (is in memory directly after next field)
	push [ecx]
	call ValidateHandler		; Validate Exception Handler
	add esp,4
	cmp eax,0
	jnz ReportIllegalHandler	; 
	mov ecx,[ecx]				; get address of exception handler

	mov ebx,[fs:[0]]
	cmp ebx,-1					; check if next field is valid
	jz DispatcherPrologue		; There is no next Exception Registration, jump over WalkChain

  WalkChain:					; Walk through Chain of Exception Registrations	
	;TODO: Validate Exception Handlers
	mov ecx,ebx
	add ecx,4
	push [ecx]
	call ValidateHandler
	add esp,4
	cmp eax,0
	jnz ReportIllegalHandler
	mov ecx,[ecx]
	
	mov ebx,[ebx]				; load the "next" field into ebx
	cmp ebx,0					; check if non valid next field (NULL)
	jz ReportError

	cmp ebx,-1					; Check if next field equals 0xffffffff
	jnz WalkChain				


  DispatcherPrologue:			; overwritten prologue of KiUserExceptionDispatcher
	CLD
	mov ecx,dword ptr ss:[esp+4]
	mov ebx,dword ptr ss:[esp]

	push offset msgEnd
	push 0
	push 2
	call _DEBUG_PRINTF
  	add esp,12

	push JmpBackAddress			; jump back to KiUserExceptionDispatcher after Prologue
	ret
	
  ReportError:
	push offset msg
	push 0
	push 2
	call _DEBUG_PRINTF
	add esp,12
	push JmpBackAddress			; jump back to KiUserExceptionDispatcher after Prologue
	ret	

  ReportIllegalHandler:
  	push offset msg2
  	push 0
  	push 2
  	call _DEBUG_PRINTF
  	add esp,12
	push [ebx]
  	push ebx
	push [ecx]
	push ecx
	push fs:[0]
	call _IllegalExceptionHandler
	add esp,20
	push JmpBackAddress			; jump back to KiUserExceptionDispatcher after Prologue
	ret	

ValidateExceptionChain endp

; Returns 1 if Handler is OK, otherwise 0
ValidateHandler proc address:dword 
	mov eax,0
	mov edx,address
	shr edx,24					; get first byte of handler

	push edx					; is it a pop inst?
	call IsPopInst
	add esp,4
	cmp eax,1					
	jz returnOk

	mov edx,address				; is 2nd byte also a pop inst?
	shr edx,16
	and edx,0ffh
	push edx 
	call IsPopInst
	add esp,4
	cmp eax,1
	jz returnOk

	mov edx,address				; is 3rd byte a ret inst?
	shr edx,8
	and edx,0ffh
	push edx 
	call IsPopInst
	add esp,4
	cmp eax,1
	jnz return

returnOk:
	mov eax,1					; everything is ok
return:
	ret
ValidateHandler endp

; Returns 1 if instruction is some form of pop, otherwise 0
IsPopInst proc inst:dword	
	mov eax,0					; assume byte is no pop inst

	cmp inst,7h					; POP ES
	jz return  

	cmp inst,17h				; POP SS
	jz return 
		
	cmp inst,57h				; 58h <= x <= 5fh are all pop instructions
	jle return					
	cmp inst,60h				
	jge return

	cmp inst,61h				; POPA
	jz return 

	mov eax,1					; opcode for pop inst found

return:
	ret

IsPopInst endp


; Returns 1 if instruction is some form of ret, otherwise 0
IsRetInst proc inst:dword	
	mov eax,0					; assume byte is no ret inst

	cmp inst,0c2h				; ret
	jz return 

	cmp inst,0c3h				; ret
	jz return 

	cmp inst,0cbh				; retf
	jz return 

	cmp inst,0cah				; retf
	jz return 

	mov eax,1					; opcode for ret inst found

return:
	ret

IsRetInst endp

end