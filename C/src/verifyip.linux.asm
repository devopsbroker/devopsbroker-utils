;
; verifyip.linux.asm - DevOpsBroker NASM file for validating IPv4 or IPv6 addresses
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
; Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
;
; This file implements the following x86-64 assembly language functions for the
; verifyip utility:
;
;   o void c009cdda_verifyIPv4(char *ipAddress);
;   o void c009cdda_verifyIPv6(char *ipAddress);
;
; echo verifyip | md5sum | cut -c 25-32
; -----------------------------------------------------------------------------
;

; ════════════════════════════ Include Directives ════════════════════════════


; ═══════════════════════════════ Preprocessor ═══════════════════════════════

; character values
%define ZERO      0x30
%define NINE      0x39
%define LOWER_A   0x61
%define LOWER_F   0x66

; Constants
%define EXIT_FAILURE   0x01

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives

; ════════════════════════════ Uninitialized Data ════════════════════════════

section .bss                ; RESX directives

; ══════════════════════════════ Assembly Code ═══════════════════════════════

	section .text

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ External Resources ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

extern  exit

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ c009cdda_verifyIPv4 ~~~~~~~~~~~~~~~~~~~~~~~~~~~

	global  c009cdda_verifyIPv4:function
c009cdda_verifyIPv4:
; Parameters:
;	rdi : char *ipAddress
; Local Variables:
;	eax : octet value
;	rsi : 64-bit char buffer
;	dx  : dl = bufSize, dh = 8
;	cx  : cl = charPos, ch = numGroups
;	r8d : data conversion register

.prologue:                            ; functions typically have a prologue
	prefetcht0 [rdi]                  ; prefetch the ipAddress string into the CPU cache
	xor        eax, eax               ; octet value = 0
	mov        dx, 0x0808             ; dh = 8, bufSize = 8
	xor        ecx, ecx               ; numGroups = 0, charPos = 0
	xor        r8d, r8d               ; clear data conversion register
	mov        rsi, [rdi]             ; load first eight characters into rsi

	; Verify the IP address from the input string
.whileIPAddress:
	test       sil, sil               ; if (ch == '\0')
	jz         .epilogue

.processCharacter:
	cmp        sil, 0x2F              ; if (ch == '/')
	je         .processCIDRSuffix

	cmp        sil, 0x2E              ; if (ch == '.')
	jne        .processDigit

	test       cl, cl                 ; if (charPos == 0)
	jz         invalidIPAddress

	inc        ch                     ; numGroups++
	cmp        ch, 0x03               ; if (numGroups > 4)
	ja         invalidIPAddress

	xor        cl, cl                 ; charPos = 0
	xor        ax, ax                 ; octet value = 0
	jmp        .manageCharBuffer

.processDigit:
	cmp        sil, NINE              ; if (ch > '9')
	jg         invalidIPAddress
	sub        sil, ZERO              ; if (ch < '0')
	jl         invalidIPAddress

	inc        cl                     ; charPos++
	mov        r8b, sil               ; value = (value * 10) + digit
	lea        eax, [eax+eax*4]
	lea        eax, [r8d+eax*2]

	cmp        ax, 0xff               ; if (octet value > 255)
	ja         invalidIPAddress

	cmp        cl, 0x03               ; if (charPos > 3)
	ja         invalidIPAddress

.manageCharBuffer:
	shr        rsi, 8                 ; shift to the next character
	dec        dl                     ; bufSize--
	inc        rdi                    ; ipAddress++

	test       dl, dl                 ; if (bufSize == 0)
	jnz        .whileIPAddress

	mov        rsi, [rdi]             ; load next eight characters into rsi
	mov        dl, dh                 ; bufSize = 8
	jmp        .whileIPAddress

.processCIDRSuffix:
	lea        r10, [rel $+12]        ; get cidrSuffix value
	jmp        getCIDRSuffixValue

	cmp        dx, 0x20               ; if (cidrSuffix > 32)
	ja         invalidIPAddress

.epilogue:                            ; functions typically have an epilogue
	test       cl, cl                 ; if (charPos == 0)
	jz         invalidIPAddress

	cmp        ch, 0x03               ; if (numGroups != 3)
	jne        invalidIPAddress

	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ c009cdda_verifyIPv6 ~~~~~~~~~~~~~~~~~~~~~~~~~~~

	global  c009cdda_verifyIPv6:function
c009cdda_verifyIPv6:
; Parameters:
;	rdi : char *ipAddress
; Local Variables:
;	ax  : al = hasShorthand
;	rsi : 64-bit char buffer
;	dx  : dl = bufSize, dh = 8
;	cx  : cl = charPos, ch = numGroups
;	r8d : data conversion register

.prologue:                            ; functions typically have a prologue
	prefetcht0 [rdi]                  ; prefetch the ipAddress string into the CPU cache
	xor        eax, eax               ; hasShorthand = false
	mov        dx, 0x0808             ; dh = 8, bufSize = 8
	xor        ecx, ecx               ; numGroups = 0, charPos = 0
	xor        r8d, r8d               ; clear data conversion register
	mov        rsi, [rdi]             ; load first eight characters into rsi

	cmp        sil, 0x3A              ; if (ch == ':')
	je         startsWithColon        ; perform starts with colon processing

	; Verify the IP address from the input string
.whileIPAddress:
	test       sil, sil               ; if (ch == '\0')
	jnz        .processCharacter

.epilogue:                            ; functions typically have an epilogue
	test       cl, cl                 ; if (charPos == 0)
	jz         invalidIPAddress

	test       al, al                 ; if (hasShorthand == false)
	jz         .return

	cmp        ch, 0x05               ; if (numGroups > 6)
	ja         invalidIPAddress

.return:
	ret                               ; pop return address from stack and jump there

.processCharacter:
	cmp        sil, 0x2F              ; if (ch == '/')
	je         .processCIDRSuffix

	cmp        sil, 0x3A              ; if (ch == ':')
	jne        .parseHex

.processColon:
	inc        ch                     ; numGroups++
	test       cl, cl                 ; if (charPos == 0)
	jz         invalidIPAddress

	cmp        ch, 0x07               ; if (numGroups > 8)
	ja         invalidIPAddress

	xor        cl, cl                 ; charPos = 0
	lea        r10, [rel $+9]         ; get next character
	jmp short  getNextCharacter

.checkForShorthand:
	cmp        sil, 0x3A              ; if (ch != ':')
	jne        .parseHex

	test       al, al                 ; if (hasShorthand == true)
	jnz        invalidIPAddress

	inc        al                     ; hasShorthand = true
	lea        r10, [rel $+9]         ; get next character
	jmp short  getNextCharacter

	test       sil, sil               ; if (ch == '\0')
	jnz        .processCharacter
	ret                               ; pop return address from stack and jump there

.parseHex:
	cmp        sil, NINE              ; if (ch > '9')
	ja         .hexadecimal
	cmp        sil, ZERO              ; if (ch >= '0')
	jae        .trackCharPos

	jmp        invalidIPAddress

.hexadecimal:
	or         sil, 0x20              ; toLowerCase(ch)
	cmp        sil, LOWER_F           ; if (ch > 'f')
	ja         invalidIPAddress
	cmp        sil, LOWER_A           ; if (ch < 'a')
	jb         invalidIPAddress

.trackCharPos:
	inc        cl                     ; charPos++
	cmp        cl, 0x04               ; if (charPos > 4)
	ja         invalidIPAddress

	lea        r10, [rel $+9]         ; get next character
	jmp short  getNextCharacter
	jmp        .whileIPAddress

.processCIDRSuffix:
	lea        r10, [rel $+9]         ; get cidrSuffix value
	jmp short  getCIDRSuffixValue

	cmp        dx, 0x80               ; if (cidrSuffix > 128)
	ja         invalidIPAddress

	jmp        .epilogue

; ═════════════════════════════ Private Routines ═════════════════════════════

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ getNextCharacter ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

getNextCharacter:
; Parameters:
;	rdi : char *ipAddress
;	rsi : 64-bit char buffer
;	dx  : dl = bufSize, dh = 8

	shr        rsi, 8                 ; shift to the next character
	dec        dl                     ; bufSize--
	inc        rdi                    ; ipAddress++

	test       dl, dl                 ; if (bufSize == 0)
	jnz        .epilogue

	mov        rsi, [rdi]             ; load next eight characters into rsi
	mov        dl, dh                 ; bufSize = 8

.epilogue:
	jmp        r10                    ; jump to the return address

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~ getCIDRSuffixValue ~~~~~~~~~~~~~~~~~~~~~~~~~~~~

getCIDRSuffixValue:
; Parameters:
;	rdi : char *ipAddress
; Local Variables:
;	edx : cidrSuffix value
;	rsi : 64-bit char buffer
;	r8d : data conversion register

	inc        rdi                    ; ipAddress++
	mov        esi, [rdi]             ; load next four characters into esi
	xor        edx, edx               ; cidrSuffix = 0
	xor        r8d, r8d               ; clear data conversion register

.whileInteger:
	cmp        sil, NINE              ; if (ch > '9')
	jg         invalidIPAddress
	sub        sil, ZERO              ; if (ch < '0')
	jl         invalidIPAddress

	mov        r8b, sil               ; value = (value * 10) + digit
	lea        edx, [edx+edx*4]
	lea        edx, [r8d+edx*2]

	shr        esi, 8                 ; shift to the next character
	test       sil, sil               ; if (ch == '\0')
	jnz        .whileInteger

.epilogue:
	jmp        r10                    ; jump to the return address

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ invalidIPAddress ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

invalidIPAddress:
	; exit(EXIT_FAILURE);
	mov        rdi, EXIT_FAILURE
	call       exit WRT ..plt

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ startsWithColon ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

startsWithColon:
; Parameters:
;	rdi : char *ipAddress
;	rsi : 64-bit char buffer
;	dx  : dl = bufSize, dh = 8
;	cx  : cl = charPos, ch = numGroups
;	r8d : bitmask register
;	r9d : temporary value register

	shr        rsi, 8                 ; shift to the second character
	cmp        sil, 0x3A              ; if (ch != ':')
	jne        invalidIPAddress

	dec        dl                     ; bufSize--
	inc        rdi                    ; ipAddress++

	dec        dl                     ; bufSize--
	inc        rdi                    ; ipAddress++

	shr        rsi, 8                 ; shift to the third character
	inc        al                     ; hasShorthand = true

	test       sil, sil               ; if (ch == '\0')
	jz         .epilogue

.isFFFF:
	mov        r9d, esi
	mov        r8d, 0x20202020        ; toLowerCase(substring)
	or         r9d, r8d

	mov        r8d, 0x66666666        ; if (substring == 'ffff')
	cmp        r9d, r8d
	jne        c009cdda_verifyIPv6.parseHex

	shr        rsi, 32                ; shift over the substring
	sub        dl, 4                  ; bufSize -= 4
	add        rdi, 4                 ; ipAddress += 4

	test       sil, sil               ; if (ch == '\0')
	jz         .epilogue

	cmp        sil, 0x2F              ; if (ch == '/')
	je         c009cdda_verifyIPv6.processCIDRSuffix

	cmp        sil, 0x3A              ; if (ch == ':')
	jne        invalidIPAddress

.possibleIPv4Address:
	inc        rdi                    ; ipAddress++
	mov        rsi, [rdi]             ; load next eight characters into rsi
	mov        dl, dh                 ; bufSize = 8

	mov        r9d, esi               ; put first four characters in r9d
	shr        r9d, 8

	cmp        r9b, 0x2E              ; look for a period
	je         c009cdda_verifyIPv4

	shr        r9d, 8
	cmp        r9b, 0x2E
	je         c009cdda_verifyIPv4

	shr        r9d, 8
	cmp        r9b, 0x2E
	je         c009cdda_verifyIPv4

.noIPv4Address:
	inc        ch                     ; numGroups++
	jmp        c009cdda_verifyIPv6.whileIPAddress

.epilogue:
	ret                               ; pop return address from stack and jump there
