; AHCIFIXD.SYS
; DOS driver complementing AHCIFIX.386 (the VxD)
;
; Purpose is to work around firmware bugs in Intel AHCI controllers, to
; prevent corruption of the EBDA. Works best if installed before EMM386!

	.386
	.model	large

; Structures
RqHdr	struc			; DOS driver request header
	bLen	db ?
	bUnit	db ?
	bCmd	db ?
	wStatus	dw ?
	_resd	dq ?
RqHdr	ends

InitRq	struc			; Init request from DOS
	sHdr	RqHdr <?>
	bUnits	db ?
	lpEnd	dd ?
	lpCmdLn	dd ?
	bDrvNum	db ?
	wErrMsg	dw ?
InitRq	ends

DD_Struc struc
DD_size		dd ?
DD_offset	dd ?
DD_segment	dw ?
DD_bufid	dw ?
DD_physaddx	dd ?
DD_Struc ends

EDD_Struc struc
EDD_size	dd ?
EDD_offset	dd ?
EDD_segment	dd ?
EDD_numavail	dw ?
EDD_numused	dw ?
EDD_physaddx	dd ?
EDD_physsize	dd ?
; And there can be more regions
EDD_Struc ends

; Equates
BDA_SEGMENT	equ 40h	; BIOS Data Area segment
EBDA_OFFSET	equ 0Eh	; Offset within BDA of pointer to Extended BDA segment
VDS_FLAG_OFFSET	equ 7Bh	; Offset within BDA of Virtual DMA Spec flags

; Macros
GET_BDA_ES	macro
	push	BDA_SEGMENT
	pop	es
	assume	es:nothing
endm

	.code
driver	segment	use16
org	0

lpNextDriver	dd -1
wAttrs		dw 08000h	; Char device, no functions supported
pStrategy	dw offset strategy
pInterrupt	dw offset init
drvName		db '$AHCIFIX'

lpSavedInt13	label dword
SavedInt13_off	dw ?
SavedInt13_seg	dw ?
lpFwInt13	label dword
FwInt13_off	dw ?
FwInt13_seg	dw ?

lpSavedInt2F	label dword
SavedInt2F_off	dw ?
SavedInt2F_seg	dw ?

lpSavedInt4B	label dword
SavedInt4B_off	dw ?
SavedInt4B_seg	dw ?

; share memory
lpInt13RetPoint	label dword
lpSavedReq	label dword
SavedReq_off	dw ?
SavedReq_seg	dw ?

Win386_Startup_Info	label byte
SIS_Version	db 3,0Ah	; version 3.10
SIS_Next_Dev	label dword
Next_Dev_off	dw ?
Next_Dev_seg	dw ?
SIS_Virt_Dev_File label dword
Virt_Dev_off	dw offset Virt_Dev_File
Virt_Dev_seg	dw ?
; retpoint of int 4Bh in the firmware (which we can pass to Windows)
SIS_Reference_Data	label dword
dodgy_int4B_retpoint	dd 0
; no instance data, since we "shouldn't" be doing anything interesting once
; Windows is fully booted...
SIS_Instance_Data	dd 0

; Default path, can be overwritten by command line
Virt_Dev_File	db "C:\WINDOWS\SYSTEM\AHCIFIX.386"
; Buffer to allow for a longer filename to be written in
		db (80h - size Virt_Dev_File) dup (0)

; Bit 0 = int 13h filters enabled
; Bit 1 = next call should go to ES:BX from int 2Fh AH=13h
Int13_Filter_Flags	db 1

; share memory between saved flags and scratchpad!
SavedFlags	label word
; A little scratchpad to store the first 6Ch bytes of the EBDA while the silly
; firmware is allowing it to be overwritten by an EDD structure. *facepalm*
; In theory, the int 4Bh call may overwrite up to 98h bytes of the EBDA, but
; from 6Ch we have disk status stuff, which the firmware itself should update
; anyway at the end of the disk transfer operation (i.e. after int 4Bh).
scratchpad	db 6Ch dup (?)

strategy	proc far
	assume	ds:nothing,es:nothing,ss:nothing
	mov	[SavedReq_off],bx
	mov	[SavedReq_seg],es
	ret
strategy	endp

; Check if VDS is available: sets CF if yes, clears it if no
Check_VDS	proc near	uses es
	GET_BDA_ES
	bt	word ptr es:[VDS_FLAG_OFFSET], 5
	ret
Check_VDS	endp

Get_EBDA_AX	proc near	uses es
	GET_BDA_ES
	mov	ax,word ptr es:[EBDA_OFFSET]
	ret
Get_EBDA_AX	endp

Int13_Filter	proc far
	assume	ds:nothing,es:nothing,ss:nothing
	test	[Int13_Filter_Flags],1
	jz	@@passthru

	call	Check_VDS
	jc	@F
@@passthru:
	btr	word ptr [Int13_Filter_Flags],1
	jc	@@firmware
	jmp	lpSavedInt13
@@firmware:
	jmp	lpFwInt13

@@:
	; VDS is available, we need to put a filter on it too while the firmware
	; is doing its thing...
	call	Hook_Int4B

	; Rearrange the stack a little before calling into the firmware
	pop	[lpInt13RetPoint]
	; Don't use POPF since that may re-enable interrupts before we're ready!
	pop	[SavedFlags]
	; Build a RETF frame for us...
	push	[lpInt13RetPoint]
	; And an IRET frame for the firmware!
	push	[SavedFlags]
	btr	word ptr [Int13_Filter_Flags],1
	jc	@F
	call	lpSavedInt13
	jmp	@@int13_done
@@:
	call	lpFwInt13

@@int13_done:
	call	Unhook_Int4B
	ret
Int13_Filter	endp

; We place this filter over the "original" int 13h reported by int 2Fh AH=13h
; to ensure we catch *any* int 4Bh calls from inside the firmware, *even if*
; someone else (e.g WDCTRL VxD Init Routine) tries to be clever and bypass DOS!
Int13_Filter_Fw	proc far
	assume	ds:nothing,es:nothing,ss:nothing
	; Set "firmware" flag
	or	[Int13_Filter_Flags],2
	jmp	Int13_Filter
Int13_Filter_Fw	endp

Hook_Int4B	proc near	uses es eax
	assume	ds:nothing,es:nothing,ss:nothing
	; Can't use int 21h AH=35h/25h since they may not be re-entrant!
	; (Remember, this is called right before we jump into the firmware
	;  so it's almost certainly on a DOS stack!)
	xor	ax,ax
	mov	es,ax

	mov	ax,cs
	cmp	ax,word ptr es:[4Bh*4+2]
	je	@F	; we somehow got re-entered after hooking int 4Bh...

	mov	eax,dword ptr es:[4Bh*4]
	mov	[lpSavedInt4B],eax

	mov	word ptr es:[4Bh*4],offset Int4B_Filter
	mov	word ptr es:[4Bh*4+2],cs
@@:
	ret
Hook_Int4B	endp

Unhook_Int4B	proc near	uses es eax
	assume	ds:nothing,es:nothing,ss:nothing
	; Can't use int 21h AH=25h since it may not be re-entrant!
	; (Remember, this is called right after we returned from the firmware
	;  so it's almost certainly on a DOS stack!)
	xor	ax,ax
	mov	es,ax
	mov	eax,[lpSavedInt4B]
	mov	dword ptr es:[4Bh*4],eax
	ret
Unhook_Int4B	endp

Int4B_Filter	proc
	assume	ds:nothing,es:nothing,ss:nothing
	cmp	ah, 81h	; really a VDS call?
	jne	@@passthru

	cmp	al, 3	; LOCK DMA REGION
	jne	@@notlock

	call	Get_EBDA_AX
	cmp	es:[di].DD_Struc.DD_segment,ax	; locking in the EBDA?
	mov	ax,8103h			; restore command!
	jne	@@passthru			; if not, we don't care...
	cmp	es:[di].DD_Struc.DD_offset,size scratchpad
	jnb	@@passthru	; if not at the beginning, we don't care...

	; backup the first 6Ch bytes of the EBDA
	push	ds
	push	es
	push	si
	push	di
	push	cx

	mov	ds,es:[di].DD_Struc.DD_segment
	mov	cx,cs
	mov	es,cx
	assume	es:driver
	xor	si,si
	lea	di,scratchpad
	mov	cx,size scratchpad SHR 2
	rep	movsd

	pop	cx
	pop	di
	pop	si
	pop	es
	assume	es:nothing
	pop	ds
	jmp	@@passthru

@@notlock:
	cmp	al,6	; SCATTER/GATHER UNLOCK DMA REGION
	je	@F
	cmp	al,4	; UNLOCK DMA REGION
	jne	@@passthru

@@:
	cmp	es:[di].DD_Struc.DD_physaddx,0
	jnz	@F

	; Firmware passed us the wrong ES
	; Swap ES/DS to sort it out...
	push	es
	push	ds
	pop	es
	pop	ds

	; return to an unswapping routine
	pop	[dodgy_int4B_retpoint]
	push	cs
	push	offset Unswap_ES_DS

@@:
	push	ax
	call	Get_EBDA_AX
	cmp	es:[di].DD_Struc.DD_segment,ax	; unlocking in the EBDA?
	pop	ax
	jne	@@passthru
	cmp	es:[di].DD_Struc.DD_offset,size scratchpad
	jnb	@@passthru		; if not at the beginning, we don't care

	; restore the first 6Ch bytes of the EBDA
	push	ds
	push	es
	push	si
	push	di
	push	cx

	mov	es,es:[di].DD_Struc.DD_segment
	mov	cx,cs
	mov	ds,cx
	assume	ds:driver
	lea	si,scratchpad
	xor	di,di
	mov	cx,size scratchpad SHR 2
	rep	movsd

	pop	cx
	pop	di
	pop	si
	pop	es
	pop	ds
	assume	ds:nothing

@@passthru:
	jmp	lpSavedInt4B
Int4B_Filter	endp

Unswap_ES_DS	proc far
	push	es
	push	ds
	pop	es
	pop	ds
	jmp	[dodgy_int4B_retpoint]
Unswap_ES_DS	endp

; int 2Fh hook to allow Windows 3.1 to communicate with us
Multiplex	proc
	cmp	ah,16h
	je	@F
@@passthru:
	jmp	lpSavedInt2F

@@:
	cmp	al,5	; Windows Initialization Notification
	je	@@win_begin_init
	cmp	al,8	; Windows Initialization Complete Notification
	je	@@win_fin_init
	cmp	al,9	; Windows Begin Exit
	je	@@win_begin_exit

	jmp	@@passthru

@@win_begin_init:
	; Step 1: call next device driver
	pushf
	call	lpSavedInt2F

	; Step 2: Initialize Win386_Startup_Info_Struc
	bt	dx,0
	jc	@@step3	; Standard Mode, we don't need to do this
	cmp	[dodgy_int4B_retpoint],0
	jz	@F	; No dodgy firmware detected, no info for Windows

	; Insert our startup info struct into the chain
	mov	[Next_Dev_off],bx
	mov	[Next_Dev_seg],es
	mov	bx,cs
	mov	es,bx
	lea	bx,Win386_Startup_Info
	jmp	@@step3

@@:
	; We didn't detect any dodgy firmware, so don't muck up any attempts
	; by the VxD initialization code to find it instead
	mov	[Int13_Filter_Flags],0

@@step3:
	; Step 3: Return using IRET without changing CX
	iret

@@win_fin_init:
	; By now, the VxD should be doing its thing, so we're not needed anymore
	mov	[Int13_Filter_Flags],0
	jmp	lpSavedInt2F

@@win_begin_exit:
	; Put our filter back in place before the VxD shuts down...
	mov	[Int13_Filter_Flags],1
	jmp	lpSavedInt2F
Multiplex	endp

; a simple "interrupt" routine that doesn't support any functions
interrupt	proc far	uses es bx
	assume	ds:nothing,es:nothing,ss:nothing
	les	bx,[lpSavedReq]
	mov	es:[bx].RqHdr.wStatus,8003h	; unknown command
	ret
interrupt	endp

end_res_code	label byte

init	proc far	uses es ds ax bx dx si di
	assume	ds:nothing,es:nothing,ss:nothing
	les	bx,[lpSavedReq]

	; Make sure this is an "init" call
	cmp	es:[bx].RqHdr.bCmd,0
	jz	@F
	mov	es:[bx].RqHdr.wStatus,8003h	; unknown command
	ret

@@:
	; Change the interrupt pointer so we don't "init" again
	mov	[pInterrupt],offset interrupt

	; Perform some checks first to make sure we're not wasting our time...
	call	Get_EBDA_AX
	mov	ds,ax
	xor	ax,ax
	mov	si,ax
	lodsb	; first byte in EBDA should be its size in kiB
	test	al,al
	jz	@@corrupt	; zero-size EBDA is not sane

	shl	ax,10-4		; convert to kiB, then to segments
	mov	dx,ds
	add	ax,dx
	cmp	ax,0A000h	; beyond end of conventional memory?
	ja	@@corrupt

	; now check the next fifteen bytes, which should all be zero...
	mov	cx,0Fh
@@:
	lodsb
	test	al,al
	jnz	@@corrupt
	loop	@B

	call	Check_VDS
	jnc	@F

	lea	dx,vdsdetected
	call	init_msg
	call	print_note

@@:
	mov	[Virt_Dev_Seg],cs
	; Parse command line...
	lds	si,es:[bx].InitRq.lpCmdLn
	cld

@@ignoreword:
	; Ignore first argument (our own filename)
	xor	cx,cx
	not	cx
	mov	al,' '
@@:	; any leading spaces
	lodsb
	cmp	al,' '
	loope	@B
@@:	; our filename itself
	lodsb
	cmp	al,' '
	loopne	@B

@@checkspaces:
	xor	cx,cx
	not	cx
@@:
	lodsb
	cmp	al,' '
	loope	@B

	call	check_eol
	jz	@@nofilename

	dec	si
	lodsw
	cmp	ah,':'		; has to be a fully-qualified filename!
	lea	si,[si-2]	; go back without affecting flags
	jne	@@ignoreword

	; Up to the filename, try to open it...
	mov	dx,si
	; Need to null-terminate it!
@@:
	lodsb
	call	check_eol
	jnz	@B
	dec	si
	mov	byte ptr ds:[si],0

	mov	ax,3D00h	; OPEN
	xor	cx,cx		; no attrs
	int	21h
	jc	@@nofilename

	; Close it again...
	mov	bx,ax
	mov	ah,3Eh		; CLOSE
	int	21h

	; Copy the name into our data segment
	mov	ax,cs
	mov	es,ax
	assume	es:driver
	mov	si,dx
	lea	di,Virt_Dev_File
@@:
	lodsb
	call	check_eol
	jz	@F
	stosb
	jmp	@B

@@nofilename:
	assume	es:nothing
	lea	dx,nofilename
	call	init_msg

@@:
	; Use int 2Fh to get the original int 13h vector.
	; To do this, we (annoyingly) have to set it to something fake
	; before changing it back...
	mov	ah,13h
	mov	dx,cs
	mov	ds,dx
	mov	es,dx
	lea	bx,Int13_Filter_Fw
	lea	dx,Int13_Filter

	pushf
	cli	; don't allow anything to accidentally call int 13h while we're doing this!
	int	2Fh
	; save the vectors
	mov	cs:[SavedInt13_off], dx
	mov	cs:[SavedInt13_seg], ds
	mov	cs:[FwInt13_off], bx
	mov	cs:[FwInt13_seg], es
	; now confirm that we do want to install our own filters
	mov	dx,cs
	mov	ds,dx
	mov	es,dx
	lea	bx,Int13_Filter_Fw
	lea	dx,Int13_Filter
	int	2Fh
	popf

	mov	ax,352Fh	; get int 2Fh vector
	int	21h
	mov	[SavedInt2F_seg],es
	mov	[SavedInt2F_off],bx
	les	bx,[lpSavedReq]

	mov	ax,252Fh	; set int 2Fh vector
	push	cs
	pop	ds
	lea	dx,Multiplex
	int	21h

	mov	es:[bx].InitRq.lpEnd,offset end_res_code
	mov	word ptr es:[bx+2].InitRq.lpEnd,cs
	mov	es:[bx].RqHdr.wStatus,100h	; OK
	ret

@@corrupt:
	lea	dx,corrupt
	call	init_msg
	call	print_note

	mov	es:[bx].InitRq.lpEnd,0		; unload
	mov	word ptr es:[bx+2].InitRq.lpEnd,cs
	mov	es:[bx].RqHdr.wStatus,800Ch	; general failure
	ret
init	endp

; Destroys AX, takes message in DX
init_msg	proc near	uses ds
	push	cs
	pop	ds
	assume	ds:driver

	mov	ah,9	; write to stdout
	int	21h
	ret

	assume	ds:nothing
init_msg	endp

; Remind the user to load us before EMM386
; Destroys AX, DX
print_note	proc near
	lea	dx,loadbeforeemm
	call	init_msg
	xor	ah,ah	; GET KEYSTROKE
	int	16h
	ret
print_note	endp

; Check if character in AL is a terminator (CR/LF/NUL) - sets ZF if so
check_eol	proc near
	cmp	al,0Dh	; end of command line!
	je	@F
	cmp	al,0Ah	; end of command line!
	je	@F
	test	al,al
@@:
	ret
check_eol	endp

; Messages
nofilename	db "No valid VxD filename given on cmdline, assuming default (AHCIFIX.386, in",0Dh,0Ah
		db "C:\WINDOWS\SYSTEM)",0Dh,0Ah,'$'
corrupt		db "EBDA is already corrupted, unloading...",0Dh,0Ah,'$'
vdsdetected	db "AHCIFIXD.SYS detected VDS during init.",0Dh,0Ah,'$'
loadbeforeemm	db "Note: for best results, you should load AHCIFIXD.SYS *before* EMM386 or similar",0Dh,0Ah
		db "Press any key to continue...",0Dh,0Ah,'$'

driver	ends

end
