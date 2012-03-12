;==================================================
;			HEADER
;==================================================

.486
.model flat, stdcall
option casemap:none

	include		\masm32\include\windows.inc
	include		\masm32\include\kernel32.inc
	include		PE_Data.inc
	includelib	\masm32\lib\kernel32.lib


;==================================================
;			DATA
;==================================================


.data
	msg_CRLF		db	13,10,0
	strLogFileName		db	"PE_Dump.log",0

	msg_hello		db	"PE_Dump of file: ",0
	msg_goodbye		db	13,10,"FINISHED.",0

	msg_err_cmdline		db	"USAGE: PE_Dump.exe <filename.exe>",0
	msg_err_open		db	"ERROR: File Open",0
	msg_err_io		db	"ERROR: File I/O",0
	msg_err_mz		db	"ERROR: Not MZ file",0
	msg_err_pe		db	"ERROR: Not PE file",0
	msg_err_rvares		db	"ERROR: RVA resolve",0


        msg_hdr                 db      13,10
				db      "ษอHEADER ออออออออออออออออออออออออออออออออ",0
        inf_sectioncnt          db      "บ Section count:         ",0
        inf_entrypoint          db      "บ Entry point:           ",0
        inf_imagebase           db      "บ Image base:            ",0
        inf_sectionalignment    db      "บ Section Alignment:     ",0
        inf_filealignment       db      "บ File Alignment:        ",0
        inf_sizeofheaders       db      "บ Size Of Headers:       ",0

        msg_dd                  db      13,10
				db      "ษอDATA DIRECTORY ออออออออออออออออออออออออ",0
        inf_dd_it_va            db      "บ Import table VA:       ",0
        inf_dd_it_sz            db      "บ Import table size:     ",0
        inf_dd_bi_va            db      "บ Bound Import VA:       ",0
        inf_dd_bi_sz            db      "บ Bound Import size:     ",0

        msg_sect                db      13,10
				db      "ษอSECTIONS ออออออออออออออออออออออออออออออ",0
        inf_sect_name           db      "ฬธ",0
        inf_sect_va             db      "บรฤ Virtual address:     ",0
        inf_sect_vs		db      "บรฤ Virtual size:        ",0
        inf_sect_rawdat_size    db      "บรฤ Size of raw data:    ",0
        inf_sect_rawdat_ptr     db      "บรฤ Pointer to raw data: ",0
        inf_sect_chars_dw       db      "บภฤ Characteristics ฤยฤ HEX: ",0
        inf_sect_chars_bit      db      "บ                    รฤ BIT: ",0

        msg_it                  db      13,10
				db	"ษอIMPORT TABLE ออออออออออออออออออออออออออ",0
        inf_it_name             db      "บ",13,10
                                db      "ฬธ",0
        inf_it_timedatestamp    db      "บรฤฤ TimeDateStamp:  ",0
        inf_it_forwarderchain   db      "บรฤฤ ForwarderChain: ",0
        msg_it_f                db      "บภฤฤ Functions ฤฟ  ",0
        inf_it_fname            db      "บ               รฤ ",0


	inf_scn01		db	"01 unknown",0
	inf_scn02		db	"02 unknown",0
	inf_scn03		db	"03 unknown",0
	inf_scn04		db	"04 unknown",0
	inf_scn05		db	"05 IMAGE_SCN_CNT_CODE",0
	inf_scn06		db	"06 IMAGE_SCN_CNT_INITIALIZED_DATA",0
	inf_scn07		db	"07 IMAGE_SCN_CNT_UNINITIALIZED_DATA",0
	inf_scn08		db	"08 unknown",0
	inf_scn09		db	"08 IMAGE_SCN_LNK_INFO",0
	inf_scn10		db	"10 unknown",0
	inf_scn11		db	"11 IMAGE_SCN_LNK_REMOVE",0
	inf_scn12		db	"12 IMAGE_SCN_LNK_COMDAT",0
	inf_scn13		db	"13 unknown",0
	inf_scn14		db	"14 unknown",0
	inf_scn15		db	"15 IMAGE_SCN_MEM_FARDATA",0
	inf_scn16		db	"16 unknown",0
	inf_scn17		db	"17 IMAGE_SCN_MEM_PURGEABLE",0
	inf_scn18		db	"18 IMAGE_SCN_MEM_LOCKED",0
	inf_scn19		db	"19 IMAGE_SCN_MEM_PRELOAD",0
	inf_scn20		db	"20 unknown align",0
	inf_scn21		db	"21 unknown align",0
	inf_scn22		db	"22 unknown align",0
	inf_scn23		db	"23 unknown align",0
	inf_scn24		db	"24 IMAGE_SCN_LNK_NRELOC_OVFL",0
	inf_scn25		db	"25 IMAGE_SCN_MEM_DISCARDABLE",0
	inf_scn26		db	"26 IMAGE_SCN_MEM_NOT_CACHED",0
	inf_scn27		db	"27 IMAGE_SCN_MEM_NOT_PAGED",0
	inf_scn28		db	"28 IMAGE_SCN_MEM_SHARED",0
	inf_scn29		db	"29 IMAGE_SCN_MEM_EXECUTE",0
	inf_scn30		db	"30 IMAGE_SCN_MEM_READ",0
	inf_scn31		db	"31 IMAGE_SCN_MEM_WRITE",0
	inf_scn32		db	"32 unknown",0

	inf_scn	dd	offset inf_scn32, offset inf_scn31, offset inf_scn30, offset inf_scn29
		dd	offset inf_scn28, offset inf_scn27, offset inf_scn26, offset inf_scn25
		dd	offset inf_scn24, offset inf_scn23, offset inf_scn22, offset inf_scn21
		dd	offset inf_scn20, offset inf_scn19, offset inf_scn18, offset inf_scn17
		dd	offset inf_scn16, offset inf_scn15, offset inf_scn14, offset inf_scn13
		dd	offset inf_scn12, offset inf_scn11, offset inf_scn10, offset inf_scn09
		dd	offset inf_scn08, offset inf_scn07, offset inf_scn06, offset inf_scn05
		dd	offset inf_scn04, offset inf_scn03, offset inf_scn02, offset inf_scn01


.data?
_data_sect_start equ $

	hConsole		dd	?	; HANDLE of console
	hFile			dd	?	; HANDLE of PE file
	hLogFile		dd	?	; HANDLE of LOG file

	FileOffset_Sections	dd	?

	fName			dd	?
	strParam		dd	?


	IT_DescriptorsCount	dd	?
	pIT_descriptors		dd	?

	dwTemp			dd	?
				db	7 dup (?)
	msg_hexnumber		db	?
	msg_hexnumber0		db	?

	ioOverlapped	OVERLAPPED	<>

	MZ_Header	HDR_MZ		<>
	PE_Header	HDR_PE		<>
	MemBuffer		db	10000h	dup (?)

_data_sect_end	equ $

;================================================
;			CODE
;================================================

.code

msgPrint 	PROTO	pString:DWORD
msgPrintHex32 	PROTO	dwNumber:DWORD
msgPrintC 	PROTO	pString:DWORD
msgPrintDW	PROTO	pString:DWORD, dwNumber:DWORD

RVA2FileOffset	PROTO	RVA:DWORD		; -> EAX, 0 if error
MemPtr2RVA	PROTO	POINTER:DWORD		; -> EAX, 0 if error

isZeroMem	PROTO	pMem:DWORD, 	Count:DWORD	; -> EAX = 0 if Zero Mem
setZeroMem	PROTO	pMem:DWORD, 	Count:DWORD

ioRead 		PROTO	pBuf:DWORD,	FilePos:DWORD,	Count:DWORD	; -> EAX=0 if failed
ioWrite		PROTO	pBuf:DWORD,	FilePos:DWORD,	Count:DWORD	; -> EAX=0 if failed
ioReadAsciiz	PROTO	pBuf:DWORD,	FilePos:DWORD			; -> EAX = Bytes readen
ioReadDwordz	PROTO	pBuf:DWORD,	FilePos:DWORD			; -> EAX = BYTES readen, including last zeroes

paraAlign 	PROTO	Number:DWORD,	nAlign:DWORD
copyAsciiz 	PROTO	pSrc:DWORD, 	pDest:DWORD	; -> EAX = end of dest buf

dumpImportTable		PROTO
dumpSectionDescriptors	PROTO
dumpSectionDescriptor 	PROTO pSection:DWORD
dumpPEHeader		PROTO

;==================================================
;			CODE.MAIN
;==================================================


start:
	; Init app
	invoke	setZeroMem, offset _data_sect_start, _data_sect_end - _data_sect_start
	invoke	GetStdHandle, STD_OUTPUT_HANDLE
	mov	hConsole, eax

	invoke  GetCommandLine
	mov	edi, eax
	mov	strParam, eax
	invoke  lstrlen, edi
	test	eax, eax
	jz	lbl_err_cmdline
	inc	edi
	mov	ecx, eax
	mov	edx, eax
	mov	al,22h
	repnz	scasb
	jnz	OSm2
	inc	edi
	jmp	CRF
OSm2:	mov	edi, strParam
	mov	ecx, edx
	mov	al,20h
	repnz	scasb
	jnz	lbl_err_cmdline
CRF:	mov	[ fName], edi

	invoke	CreateFile, offset strLogFileName, GENERIC_WRITE, \
		FILE_SHARE_READ, 0, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0
	cmp	eax, INVALID_HANDLE_VALUE
	je	lbl_err_open
	mov	hLogFile, EAX


	invoke	msgPrint,  offset msg_hello
	invoke  msgPrintC, edi

	; PE file Open
	invoke	CreateFile, edi, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0
	cmp	eax, INVALID_HANDLE_VALUE
	je	lbl_err_open
	mov	hFile, eax



;================================================
;	Read File Headers
;================================================

	invoke	ioRead, offset MZ_Header, 0, SIZEOF (HDR_MZ)	; Read DOS-Stub header
	test	EAX, EAX
	jz	lbl_err_io
	cmp	MZ_Header.e_magic, "ZM"
	jne	lbl_err_mz

	invoke	ioRead, offset PE_Header, MZ_Header.e_lfanew, SIZEOF (HDR_PE)
	test	EAX, EAX
	jz	lbl_err_io
	cmp	WORD PTR [PE_Header], "EP"
	jne	lbl_err_pe

	mov	eax, MZ_Header.e_lfanew
	add	eax, SIZEOF (HDR_PE)
	mov	FileOffset_Sections, eax


	xor	eax, eax
	mov	edi, offset MemBuffer
	mov	ebx, SIZEOF (SECTION_DESCRIPTOR)
	mov	ax,  PE_Header.NumberOfSections
	mul	bl
	push	eax
	invoke	ioRead, edi, FileOffset_Sections, eax
	test	eax, eax
	pop	eax
	jz	lbl_err_io


	add	eax, edi
	shl	ebx, 2
	add	eax, ebx
	mov	pIT_descriptors, eax
	sub	eax, edi


	call	dumpPEHeader
	call	dumpSectionDescriptors

;================================================
;
;	read IMPORT TABLE
;
;================================================


	; -------------------
	; read IT Descriptors
	;

	invoke	RVA2FileOffset, PE_Header.DD_ImportTable.VirtualAddress
	test	EAX, EAX
	jz	lbl_err_rvares
	mov	edx, eax
	mov	edi, pIT_descriptors
	mov	ecx, SIZEOF (HDR_IMPORT_DESCRIPTOR)
lbl_ITlp:	invoke	ioRead, edi, edx, ecx
		test	eax, eax
		jz	lbl_err_io
		invoke	isZeroMem, edi, ecx
		test	eax, eax
		jz	lbl_ITfin
		add	edi, ecx
		add	edx, ecx
		inc	IT_DescriptorsCount
		jmp	lbl_ITlp
lbl_ITfin:
	shl	ecx, 1
	add	edi, ecx

	; -------------------------------------
	; read DLL names, original thunk table,
	; make mirror of original thunk table

	mov	ecx, IT_DescriptorsCount
	mov	esi, pIT_descriptors

lbl_th01:
		; Read DLL Name
		invoke	RVA2FileOffset, [ ESI + HDR_IMPORT_DESCRIPTOR.Name1 ]
		test	eax, eax
		jz	lbl_err_rvares
		invoke	ioReadAsciiz, edi, eax
		test	EAX, EAX
		jz	lbl_err_io
		mov	[ ESI + HDR_IMPORT_DESCRIPTOR.Name1 ], EDI
		add	EDI, EAX

		; Read thunk table
		invoke	RVA2FileOffset, [ ESI + HDR_IMPORT_DESCRIPTOR.OriginalFirstThunk ]
		test	eax, eax
		jz	lbl_err_rvares
		invoke	ioReadDwordz, edi, eax
		test	EAX, EAX
		jz	lbl_err_io
		mov	[ ESI + HDR_IMPORT_DESCRIPTOR.OriginalFirstThunk ], edi

		; Make mirror of thunk table
		push	ecx
		xchg	ebx, esi
		mov	esi, edi
		mov	ecx, eax
		add	EDI, EAX
		mov	[ ebx + HDR_IMPORT_DESCRIPTOR.FirstThunk ], edi
lbl_th6:	lodsb
		stosb
		loop	lbl_th6
		xchg	esi, ebx
		pop	ecx

		add	ESI, SIZEOF (HDR_IMPORT_DESCRIPTOR)
		loop	lbl_th01

	; -------------------------------------
	; read Import by name (function asciiz)
	;
	mov	ecx, IT_DescriptorsCount
	mov	esi, pIT_descriptors

lbl_th03:
		push	ecx
		push	esi

		mov	ESI, [ ESI + HDR_IMPORT_DESCRIPTOR.OriginalFirstThunk ]	; ptr

lbl_th04:		lodsd
			mov	[ esi - 4 ], edi	; new ptr 2 mem
			test	eax, eax
			jnz	lbl_th045
			mov	[ esi - 4 ], eax	; 00
			jmp	lbl_th05
lbl_th045:
			invoke	RVA2FileOffset, eax
			test	eax, eax
			jz	lbl_err_rvares
			push	eax
			invoke	ioRead, edi, eax, 2	; index word
			test	eax, eax
			pop	eax
			jz	lbl_err_io
			add	edi, 2
			add	eax, 2
			invoke	ioReadAsciiz, edi, eax
			test	eax, eax
			jz	lbl_err_io
			add	edi, eax
			jmp	lbl_th04
lbl_th05:	pop	esi
		pop	ecx

		add	ESI, SIZEOF (HDR_IMPORT_DESCRIPTOR)
		loop	lbl_th03

	call dumpImportTable

lbl_fin:
	invoke	msgPrintC, offset msg_goodbye

	push	hFile
	call	CloseHandle
	push	hLogFile
	call	CloseHandle

	push	0
	call	ExitProcess

;================================================
;	ERROR Exits
;================================================


lbl_err_open:		push	offset msg_err_open
			jmp	lbl_er_00
lbl_err_cmdline:	push	offset msg_err_cmdline	
			jmp	lbl_er_00
lbl_err_rvares:		push	offset msg_err_rvares
			jmp	lbl_er_01

lbl_err_pe:		push	offset msg_err_pe
			jmp	lbl_er_01
lbl_err_mz:		push	offset msg_err_mz
			jmp	lbl_er_01

lbl_err_io:		push	offset msg_err_io

lbl_er_01:		push	hFile
			call	CloseHandle
			push	hLogFile
			call	CloseHandle

lbl_er_00:		call	msgPrintC
			push	1
			call	ExitProcess

;------------------------------------------------
;
;		PROCS
;
;------------------------------------------------

copyAsciiz proc pSrc:DWORD, pDest:DWORD
	push	esi
	push	edi
	mov	esi, pSrc
	mov	edi, pDest
lbl_ca1:	lodsb
		stosb
		test	al, al
		jnz	lbl_ca1
	mov	eax, edi
	pop	edi
	pop	esi
	ret
copyAsciiz endp

;------------------------------------------------

msgPrint proc	pString:DWORD
		pushad
		mov	ebx, pString
		mov	esi, ebx
		xor	ecx, ecx
lbl_pc:		lodsb
		inc	ecx
		test	al,al
		jnz	lbl_pc
		dec	ecx
		xor	edx, edx
		push	edx		; lpOverlapped 	
		push	offset dwTemp	; lpNumberOfBytesWritten
		push	ecx		; nNumberOfBytesToWrite
		push	ebx		; lpBuffer
		push	hLogFile	; hFile
		push	edx		; lpReserved
		push	edx		; lpNumberOfCharsWritten
		push	ecx		; nNumberOfCharsToWrite
		push	ebx		; lpBuffer
		push	hConsole	; hConsoleOutput
		call	WriteConsoleA
		call	WriteFile
		popad
		ret
msgPrint endp

;------------------------------------------------

hextab		db	"0123456789ABCDEF"
msgPrintHex32 proc	dwNumber:DWORD
		pushad
		mov	EBX, offset hextab
		mov	EDI, offset msg_hexnumber
		mov	ECX, 8
		mov	eax, dwNumber
lbl_h1:			push	eax
			and	eax, 0Fh
			xlat
			mov	byte ptr [EDI],al
			dec	edi
			pop	eax
			shr	eax,4
			loop	lbl_h1
		xchg	eax,edi
		inc	eax
		push	eax
		call	msgPrint
		popad
		ret
msgPrintHex32 endp

;------------------------------------------------

msgPrintC proc	pString:DWORD
		pushad
		push	pString
		call	msgPrint
		push	offset msg_CRLF
		call	msgPrint
		popad
		ret
msgPrintC endp

;------------------------------------------------

msgPrintDW proc	pString:DWORD, dwNumber:DWORD
		pushad
		push	pString
		call	msgPrint
		push	dwNumber
		call	msgPrintHex32
		push	offset msg_CRLF
		call	msgPrint
		popad
		ret
msgPrintDW endp

;------------------------------------------------

RVA2FileOffset	proc	RVA:DWORD
		pushad
		mov	edx, RVA
		mov	esi, PE_Header.ImageBase
		add	edx, esi
		mov	edi, offset MemBuffer
		xor	ecx, ecx
		mov	cx,  PE_Header.NumberOfSections
lbl_rva2fo1:	mov	eax, [edi + SECTION_DESCRIPTOR.VirtualAddress]
		add	eax, esi
		mov	ebx, [edi + SECTION_DESCRIPTOR.SizeOfRawData]
		add	ebx, eax
		cmp	edx, eax
		jc	lbl_rva2fo2		; jmp if not >=
		cmp	edx, ebx
		ja	lbl_rva2fo2		; jmp if not <=
		sub	edx, eax		; EDX = Address offset in section
		add	edx, [edi + SECTION_DESCRIPTOR.PointerToRawData]
		jmp	lbl_rva2fo3
lbl_rva2fo2:	add	edi, SIZEOF(SECTION_DESCRIPTOR)
		loop	lbl_rva2fo1
		xor	edx, edx
lbl_rva2fo3:	mov	RVA, edx
		popad
		mov	eax, RVA
		ret
RVA2FileOffset endp


;------------------------------------------------

isZeroMem proc	pMem:DWORD, Count:DWORD

		push	ecx
		push	esi
		mov	esi, pMem
		mov	ecx, Count
		xor	eax,eax
lbl_zm1:	lodsb
		test	al, al
		loopz	lbl_zm1
		pop	esi
		pop	ecx
		ret

isZeroMem endp

;------------------------------------------------

setZeroMem proc	pMem:DWORD, Count:DWORD
		pushad
		mov	edi, pMem
		mov	ecx, Count
		xor	AX, AX
		rep	stosb
		popad
		ret
setZeroMem endp

;------------------------------------------------

ioRead proc	pBuf:DWORD, FilePos:DWORD, Count:DWORD
		pushad
		mov	eax, FilePos
		mov	ioOverlapped.loffset, eax
		push	offset ioOverlapped	; lpOverlapped
		push	0			; lpNumberOfBytesRead
		push	Count			; nNumberOfBytesToRead
		push	pBuf			; lpBuffer
		push	hFile			; hFile
		call	ReadFile
		mov	pBuf,eax
		popad
		mov	eax,pBuf
		ret
ioRead endp

;------------------------------------------------


ioWrite proc pBuf:DWORD, FilePos:DWORD, Count:DWORD
		pushad
		mov	eax, FilePos
		mov	ioOverlapped.loffset, eax
		invoke	WriteFile, hFile, pBuf, Count, 0, offset ioOverlapped
		mov	pBuf, eax
		popad
		mov	eax, pBuf
		ret
ioWrite endp

;------------------------------------------------

ioReadAsciiz proc pBuf:DWORD, FilePos:DWORD
		pushad
		mov	ebx, pBuf
		mov	esi, ebx
		mov	edi, ebx
		mov	edx, FilePos
		mov	ecx, 1
lbl_iora1:		invoke	ioRead, ebx , edx , ecx
			test	eax, eax
			jz	lbl_iora2
			inc	ebx
			inc	edx
			lodsb
			test	al, al
			jnz	lbl_iora1
		sub	ESI, EDI
		mov	EAX, ESI
lbl_iora2:	mov	pBuf, eax
		popad
		mov	eax, pBuf
		ret
ioReadAsciiz endp

;------------------------------------------------

ioReadDwordz proc pBuf:DWORD, FilePos:DWORD
		pushad
		mov	ebx, pBuf
		mov	esi, ebx
		mov	edi, ebx
		mov	edx, FilePos
		mov	ecx, 4
lbl_iora1:		invoke	ioRead, ebx , edx , ecx
			test	eax, eax
			jz	lbl_iora2
			add	ebx, ecx
			add	edx, ecx
			lodsd
			test	eax, eax
			jnz	lbl_iora1
		sub	ESI, EDI
		mov	EAX, ESI
lbl_iora2:	mov	pBuf, eax
		popad
		mov	eax, pBuf
		ret
ioReadDwordz endp


;------------------------------------------------

paraAlign proc Number:DWORD, nAlign:DWORD
		push	ebx
		push	edx
		mov	eax, Number
		push	eax
		mov	ebx, nAlign
		xor	edx, edx
		div	ebx
		test	edx, edx
		jz	lbl_aligned             
	

	add	esp, 4
		inc	eax
		mul	bx
		push	dx
		push	ax
lbl_aligned:	pop	eax
		pop	edx
		pop	ebx
		ret
paraAlign endp

;==================================================
;			DUMP Procs
;==================================================

dumpPEHeader proc
	pushad
	invoke	msgPrintC, offset msg_hdr
	xor	edx, edx
	mov	dx,  PE_Header.NumberOfSections
	invoke	msgPrintDW, offset inf_sectioncnt, edx
	invoke	msgPrintDW, offset inf_entrypoint, PE_Header.AddressOfEntryPoint
	invoke	msgPrintDW, offset inf_imagebase, PE_Header.ImageBase
	invoke	msgPrintDW, offset inf_sectionalignment, PE_Header.SectionAlignment
	invoke	msgPrintDW, offset inf_filealignment, PE_Header.FileAlignment
	invoke	msgPrintDW, offset inf_sizeofheaders, PE_Header.SizeOfHeaders
	invoke  msgPrintC,  offset msg_dd
	invoke	msgPrintDW, offset inf_dd_it_va, PE_Header.DD_ImportTable.VirtualAddress
	invoke	msgPrintDW, offset inf_dd_it_sz, PE_Header.DD_ImportTable.isize
	invoke	msgPrintDW, offset inf_dd_bi_va, PE_Header.DD_BoundImportTable.VirtualAddress
	invoke	msgPrintDW, offset inf_dd_bi_sz, PE_Header.DD_BoundImportTable.isize

	popad
	ret
dumpPEHeader endp

;==================================================

dumpSectionDescriptors proc
	pushad
	invoke	msgPrintC, offset msg_sect
	xor	ecx, ecx
	mov	cx,  PE_Header.NumberOfSections
	mov	edi, offset MemBuffer
lbl_sd01:	invoke	dumpSectionDescriptor, edi
		add	edi, SIZEOF(SECTION_DESCRIPTOR)
		loop	lbl_sd01
	popad
	ret
dumpSectionDescriptors endp


;==================================================

dumpSectionDescriptor proc pSection:DWORD
	pushad
		mov	ecx, 32
		mov	ebx, 1
		mov	edx, [ edi + SECTION_DESCRIPTOR.Characteristics]
		mov	edi, pSection
		mov	esi, offset inf_scn
		invoke	msgPrint,   offset inf_sect_name
		invoke	msgPrintC,  edi
		invoke  msgPrintDW, offset inf_sect_va, [ edi + SECTION_DESCRIPTOR.VirtualAddress ]
		invoke	msgPrintDW, offset inf_sect_vs, [ edi + SECTION_DESCRIPTOR.VirtualSize ]
		invoke	msgPrintDW, offset inf_sect_rawdat_size, [ edi + SECTION_DESCRIPTOR.SizeOfRawData ]
		invoke	msgPrintDW, offset inf_sect_rawdat_ptr, [ edi + SECTION_DESCRIPTOR.PointerToRawData ]
		invoke	msgPrintDW, offset inf_sect_chars_dw, edx
lbl_sd_charsbit:	test	edx, ebx
			jz	lbl_sd_charsbitnext
			invoke	msgPrint, offset inf_sect_chars_bit
			mov	eax, ecx
			shl	eax, 2
			invoke	msgPrintC, [ esi + eax ]
lbl_sd_charsbitnext:	shl	ebx, 1
			loop	lbl_sd_charsbit
	popad
	ret
dumpSectionDescriptor endp

;==================================================

dumpImportTable proc
	pushad
	invoke	msgPrintC, offset msg_it
	mov	ECX, IT_DescriptorsCount
	mov	ESI, pIT_descriptors
lbl_dIT1:	invoke	msgPrint,   offset inf_it_name
		invoke	msgPrintC,  [ ESI + HDR_IMPORT_DESCRIPTOR.Name1 ]
		invoke	msgPrintDW, offset inf_it_timedatestamp, [ ESI + HDR_IMPORT_DESCRIPTOR.TimeDateStamp ]
		invoke	msgPrintDW, offset inf_it_forwarderchain, [ ESI + HDR_IMPORT_DESCRIPTOR.ForwarderChain ]
		invoke	msgPrintC,  offset msg_it_f
		push	esi
		mov	esi, [ esi + HDR_IMPORT_DESCRIPTOR.OriginalFirstThunk ]
lbl_dIT2:		lodsd
			test	eax, eax
			jz	lbl_dIT3
			add	eax, 2
			invoke	msgPrint,  offset inf_it_fname
			invoke	msgPrintC, eax
			jmp	lbl_dIT2
lbl_dIT3:	pop	esi
		add	ESI, SIZEOF (HDR_IMPORT_DESCRIPTOR)
		loop	lbl_dIT1
	popad
	ret
dumpImportTable endp




end start