;
; scriptinfo.linux.asm - DevOpsBroker NASM file for the scriptinfo utility
;
; Copyright (C) 2019-2020 Edward Smith <edwardsmith@devopsbroker.org>
;
; This program is free software: you can redistribute it and/or modify it under
; the terms of the GNU General Public License as published by the Free Software
; Foundation, either version 3 of the License, or (at your option) any later
; version.
;
; This program is distributed in the hope that it will be useful, but WITHOUT
; ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
; FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
; details.
;
; You should have received a copy of the GNU General Public License along with
; this program.  If not, see <http://www.gnu.org/licenses/>.
;
; -----------------------------------------------------------------------------
; Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-15
;
; This file implements the following x86-64 assembly language functions for the
; scriptinfo utility:
;
;   o char *f67f16c0_getScriptName(char *pathName);
;
; echo scriptinfo | md5sum | cut -c 25-32
; -----------------------------------------------------------------------------
;

; ════════════════════════════ Include Directives ════════════════════════════


; ═══════════════════════════════ Preprocessor ═══════════════════════════════


; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives

; ════════════════════════════ Uninitialized Data ════════════════════════════

section .bss                ; RESX directives

; ══════════════════════════════ Assembly Code ═══════════════════════════════

	global  f67f16c0_getScriptName:function
	section .text
f67f16c0_getScriptName:
; Parameters:
;	rdi : char *pathName
; Local Variables:
;	rax : char *scriptName
;	rsi : 64-bit char buffer
;	dh  : bufSize

.prologue:                            ; functions typically have a prologue
	prefetcht0 [rdi]                  ; prefetch the pathName string into the CPU cache
	xor        rax, rax               ; scriptName = NULL
	mov        dx, 0x082F             ; dh = 8, dl = '/'
	mov        cx, 0x0008             ; ch = 0, cl = 8
	mov        rsi, [rdi]             ; load first eight characters into rsi

.findLastPathSeparator:
	test       sil, sil               ; if (ch == '\0')
	jz         .adjustScriptName

	cmp        sil, dl                ; if (ch == '/')
	jne        .manageCharBuffer
	mov        rax, rdi

.manageCharBuffer:
	shr        rsi, 8                 ; shift to the next character
	dec        dh                     ; bufSize--
	inc        rdi                    ; pathName++

	test       dh, dh                 ; if (bufSize == 0)
	jnz        .findLastPathSeparator

	mov        rsi, [rdi]             ; load next eight characters into rsi
	mov        dh, cl                 ; bufSize = 8
	jmp        .findLastPathSeparator

.adjustScriptName:
	test       rax, rax               ; if (scriptName != NULL)
	jz         .epilogue

	mov        [rax], ch              ; (*scriptName) = '\0'
	inc        rax                    ; scriptName++

.epilogue:                            ; functions typically have an epilogue
	ret                               ; pop return address from stack and jump there
