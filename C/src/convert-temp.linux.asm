;
; convert-temp.asm - DevOpsBroker NASM file for the convert-temp utility
;
; Copyright (C) 2018-2020 Edward Smith <edwardsmith@devopsbroker.org>
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
; Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-39
;
; This file implements the following x86-64 assembly language functions for the
; convert-temp utility:
;
;   o float b9ac2bf7_convertTemperature(char *inputTemp, TemperatureType fromTempType, TemperatureType toTempType);
;   o void b9ac2bf7_invalidTemperature(char *programName, char *temperature);
;   o void b9ac2bf7_invalidTemperatureType(char *programName, char *tempType);
;   o void b9ac2bf7_missingParameter(char *programName, char *paramName);
;   o void b9ac2bf7_usageMessage(char *fromTempTypeStr, char *toTempTypeStr, TemperatureType fromTempType);
;
; echo convert-temp | md5sum | cut -c 25-32
; -----------------------------------------------------------------------------
;

; ════════════════════════════ Include Directives ════════════════════════════


; ═══════════════════════════════ Preprocessor ═══════════════════════════════

%define ZERO        0x30
%define NINE        0x39

; enum TemperatureType
%define CELSIUS     0x43
%define FAHRENHEIT  0x46
%define KELVIN      0x4B

; float Values
%define NEG_ONE     0xbf800000        ; -1.0f
%define TEN         0x41200000        ; 10.0f
%define THIRTY_TWO  0x42000000        ; 32.0f

%define CELSIUS_FACTOR  0x3fe66666    ; 1.8f
%define KELVIN_SCALE    0x43889333    ; 273.15f

%define ERROR_CODE  0x800000          ; FLT_MIN

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives
	align 8,db 0
	invalidParamMsgFormat:  db    "[1m%s: [91m%s[0m", 0x0a, 0x0a, 0
	align 8,db 0

; ════════════════════════════ Uninitialized Data ════════════════════════════

section .bss                ; RESX directives

; ══════════════════════════════ Assembly Code ═══════════════════════════════

	global  b9ac2bf7_convertTemperature:function
	section .text
b9ac2bf7_convertTemperature:
; Parameters:
;	rdi : char *inputTemp
;	rsi : TemperatureType fromTempType
;	rdx : TemperatureType toTempType
; Local Variables:
;   r8b : byte numChars
;   r9b : bool isNegative

.prologue:                            ; functions typically have a prologue
	mov        rcx, [rdi]             ; put first eight characters into rcx
	xor        r8d, r8d               ; numChars = 0
	xor        r9d, r9d               ; isNegative = false
	pxor       xmm0, xmm0             ; value = 0

	mov        eax, TEN
	movd       xmm2, eax

	cmp        cl, 0x2D               ; '-'
	jne        .LIF0

	mov        r9b, cl                ; isNegative = true
	inc        r8b                    ; numChars++
	shr        rcx, 8                 ; shift to the next character

.LIF0:                                ; if (ch < '0' || ch > '9')
	cmp        cl, NINE
	jg         .invalidTemperature    ; Error if character greater than nine
	sub        cl, ZERO
	jl         .invalidTemperature    ; Error if character less than zero

.modifyValue:
	mulss      xmm0, xmm2             ; value = (value * 10) + digit
	movzx      eax, cl
	cvtsi2ss   xmm1, eax
	addss      xmm0, xmm1

	inc        r8b                    ; numChars++
	shr        rcx, 8                 ; shift to the next character

	; while (ch && ch != '.' && numChars < 8)
	cmp        cl, 0x2E               ; '.'
	je         .processDecimal
	test       cl, cl                 ; '\0'
	jz         .convertTemperature
	cmp        r8b, 8
	jne short  .LIF0
	; Error if we already processed eight characters

.invalidTemperature:
	mov        eax, ERROR_CODE        ; Set return value to error_code
	movd       xmm0, eax
	ret                               ; pop return address from stack and jump there

.processDecimal:
	shr        rcx, 8                 ; shift to the next character

	cmp        cl, NINE               ; if (ch < '0' || ch > '9')
	jg         .invalidTemperature    ; Error if character greater than nine
	sub        cl, ZERO
	jl         .invalidTemperature    ; Error if character less than zero

	movzx      eax, cl                ; value += (digit / 10)
	cvtsi2ss   xmm1, eax
	divss      xmm1, xmm2
	addss      xmm0, xmm1

	shr        rcx, 8                 ; shift to the next character

	test       cl, cl                 ; '\0'
	jz         .convertTemperature

.secondDecimalPlace:
	cmp        cl, NINE               ; if (ch < '0' || ch > '9')
	jg         .invalidTemperature    ; Error if character greater than nine
	sub        cl, ZERO
	jl         .invalidTemperature    ; Error if character less than zero

	movzx      eax, cl                ; value += (digit / 100)
	cvtsi2ss   xmm1, eax
	divss      xmm1, xmm2
	divss      xmm1, xmm2
	addss      xmm0, xmm1

.convertTemperature:
	test       r9b, r9b               ; if (isNegative)
	jz         .processFromTempType

	mov        eax, NEG_ONE           ; value *= -1.0f
	movd       xmm1, eax
	mulss      xmm0, xmm1

.processFromTempType:
	cmp        sil, CELSIUS
	je         fromCelsius
	cmp        sil, FAHRENHEIT
	je         fromFahrenheit

fromKelvin:
	cmp        dl, KELVIN
	jne        .toCelsius
	ret                               ; pop return address from stack and jump there

.toCelsius:                           ; value -= 273.15
	mov        eax, KELVIN_SCALE
	movd       xmm1, eax
	subss      xmm0, xmm1

	cmp        dl, FAHRENHEIT
	je         fromCelsius.toFahrenheit
	ret                               ; pop return address from stack and jump there

fromFahrenheit:
	cmp        dl, FAHRENHEIT
	jne        .toCelsius
	ret                               ; pop return address from stack and jump there

.toCelsius:                           ; value = (value - 32) ÷ 1.8
	mov        eax, THIRTY_TWO
	movd       xmm1, eax
	subss      xmm0, xmm1

	mov        eax, CELSIUS_FACTOR
	movd       xmm1, eax
	divss      xmm0, xmm1

	cmp        dl, KELVIN
	je         fromCelsius.toKelvin
	ret                               ; pop return address from stack and jump there

fromCelsius:
	cmp        dl, FAHRENHEIT
	je         .toFahrenheit
	cmp        dl, KELVIN
	je         .toKelvin
	ret                               ; pop return address from stack and jump there

.toKelvin:                            ; value += 273.15
	mov        eax, KELVIN_SCALE
	movd       xmm1, eax
	addss      xmm0, xmm1
	ret                               ; pop return address from stack and jump there

.toFahrenheit:                        ; value = (value * 1.8) + 32
	mov        eax, CELSIUS_FACTOR
	movd       xmm1, eax
	mulss      xmm0, xmm1

	mov        eax, THIRTY_TWO
	movd       xmm1, eax
	addss      xmm0, xmm1
	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~~~ b9ac2bf7_invalidTemperature ~~~~~~~~~~~~~~~~~~~~~~~~

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives
	align 8,db 0
	invalidTemp:      db    "Invalid temperature: '", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	align 8,db 0

; ══════════════════════════════ Assembly Code ═══════════════════════════════

;	TODO: Opportunity to make this pattern a function of its own

	global  b9ac2bf7_invalidTemperature:function
	extern  stderr
	extern  fprintf
	section .text
b9ac2bf7_invalidTemperature:
; Parameters:
;	rdi : char *programName
;	rsi : char *temperature

.prologue:                            ; functions typically have a prologue
	lea        rcx, [rel invalidTemp]
	lea        rdx, [rcx+22]

.populateErrorMessage:
	mov        r8, [rsi]              ; put first eight characters into r8
	mov        [rdx], r8              ; populate error message

.loop:
	test       r8b, r8b
	jz         .finish
	inc        rdx
	shr        r8, 8                  ; shift to the next character
	jmp        .loop

.finish:
	mov        [rdx], word 0x27

.fprintf:                             ; fprintf(stderr, errorMsgFormat, programName, errorMessage)
	mov        rdx, rdi               ; programName
	mov        rdi, [rel stderr]      ; FILE *stderr
	lea        rsi, [rel invalidParamMsgFormat]
	xor        eax, eax

	sub        rsp, 8                 ; align stack pointer before call
	call       fprintf wrt ..plt
	add        rsp, 8                 ; re-align stack pointer after call

	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~ b9ac2bf7_invalidTemperatureType ~~~~~~~~~~~~~~~~~~~~~~

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives
	align 8,db 0
	invalidTempType:  db    "Invalid temperature type: '", 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
	align 8,db 0

; ══════════════════════════════ Assembly Code ═══════════════════════════════

;	TODO: Opportunity to make this pattern a function of its own

	global  b9ac2bf7_invalidTemperatureType:function
	extern  stderr
	extern  fprintf
	section .text
b9ac2bf7_invalidTemperatureType:
; Parameters:
;	rdi : char *programName
;	rsi : char *tempType

.prologue:                            ; functions typically have a prologue
	lea        rcx, [rel invalidTempType]
	lea        rdx, [rcx+27]

.populateErrorMessage:
	mov        r8, [rsi]              ; put first eight characters into r8
	mov        [rdx], r8              ; populate error message

.loop:
	test       r8b, r8b
	jz         .finish
	inc        rdx
	shr        r8, 8                  ; shift to the next character
	jmp        .loop

.finish:
	mov        [rdx], word 0x27

.fprintf:                             ; fprintf(stderr, errorMsgFormat, programName, errorMessage)
	mov        rdx, rdi               ; programName
	mov        rdi, [rel stderr]      ; FILE *stderr
	lea        rsi, [rel invalidParamMsgFormat]
	xor        eax, eax

	sub        rsp, 8                 ; align stack pointer before call
	call       fprintf wrt ..plt
	add        rsp, 8                 ; re-align stack pointer after call

	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~~~~~ b9ac2bf7_missingParameter ~~~~~~~~~~~~~~~~~~~~~~~~

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives
	align 8,db 0
	missingParamMsgFormat:  db    "[1m%s: [91mMissing %s parameter[0m", 0x0a, 0x0a, 0
	align 8,db 0

; ══════════════════════════════ Assembly Code ═══════════════════════════════

;	TODO: Opportunity to make this a function of its own

	global  b9ac2bf7_missingParameter:function
	extern  stderr
	extern  fprintf
	section .text
b9ac2bf7_missingParameter:
; Parameters:
;	rdi : char *programName
;	rsi : char *paramName

.fprintf:                             ; fprintf(stderr, errorMsgFormat, programName, paramName)
	mov        rdx, rdi               ; programName
	mov        rcx, rsi               ; paramName
	mov        rdi, [rel stderr]      ; FILE *stderr
	lea        rsi, [rel missingParamMsgFormat]
	xor        eax, eax

	sub        rsp, 8                 ; align stack pointer before call
	call       fprintf wrt ..plt
	add        rsp, 8                 ; re-align stack pointer after call

	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~~~~~~ b9ac2bf7_usageMessage ~~~~~~~~~~~~~~~~~~~~~~~~~~~

; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives
	align 8,db 0
	usageMsgFormat:   db    "[1mUsage: [93m%s[0m", 0x0a, 0
	align 8,db 0
	celsiusToMsg:     db    " { fahrenheit | kelvin }", 0
	align 8,db 0
	fahrenheitToMsg:  db    " { celsius | kelvin }", 0
	align 8,db 0
	kevlinToMsg:      db    " { celsius | fahrenheit }", 0
	align 8,db 0
	tempParamStr:     db    " TEMPERATURE", 0
	align 8,db 0
	buffer:                  times 48 db 0

; ══════════════════════════════ Assembly Code ═══════════════════════════════

;	TODO: Opportunity to make this a function of its own

	global  b9ac2bf7_usageMessage:function
	extern  stderr
	extern  fprintf
	section .text
b9ac2bf7_usageMessage:
; Parameters:
;	rdi : char *fromTempTypeStr
;	rsi : char *toTempTypeStr
;	rdx : TemperatureType fromTempType
; Local Variables:
;   r10 : char *bufferPtr
;   r9b : bool isNegative

.prologue:                            ; functions typically have a prologue
	lea        rcx, [rel buffer]
	mov        r10, rcx               ; char *bufferPtr = buffer

	call       populateBuffer         ; populate buffer with fromTempTypeStr

	test       rsi, rsi
	jz         .noToTempType

	mov        [r10], byte 0x20       ; add space
	inc        r10

	mov        rdi, rsi               ; populate buffer with toTempTypeStr
	call       populateBuffer

	jmp        .tempParam

.noToTempType:
	cmp        dl, CELSIUS
	je         .fromCelsius
	cmp        dl, FAHRENHEIT
	je         .fromFahrenheit

.fromKelvin:                          ; populate buffer with kevlinToMsg
	lea        rdi, [rel kevlinToMsg]
	call       populateBuffer
	jmp        .tempParam

.fromCelsius:                         ; populate buffer with celsiusToMsg
	lea        rdi, [rel celsiusToMsg]
	call       populateBuffer
	jmp        .tempParam

.fromFahrenheit:                      ; populate buffer with fahrenheitToMsg
	lea        rdi, [rel fahrenheitToMsg]
	call       populateBuffer

.tempParam:                           ; populate buffer with tempParamStr
	lea        rdi, [rel tempParamStr]
	call       populateBuffer

.fprintf:                             ; fprintf(stderr, usageMsgFormat, buffer)
	mov        rdi, [rel stderr]      ; FILE *stderr
	lea        rsi, [rel usageMsgFormat]
	mov        rdx, rcx               ; buffer
	xor        eax, eax

	sub        rsp, 8                 ; align stack pointer before call
	call       fprintf wrt ..plt
	add        rsp, 8                 ; re-align stack pointer after call

	ret                               ; pop return address from stack and jump there

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ populateBuffer ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

populateBuffer:
	mov        r11, [rdi]              ; put rdi parameter into r11
	mov        [r10], r11              ; populate first eight characters into [r10]

.findNull:
	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	shr        r11, 8                 ; shift to the next character

	test       r11b, r11b
	jz         .epilogue

	inc        r10
	lea        rdi, [rdi+8]           ; copy next chunk of rdi parameter
	mov        r11, [rdi]
	mov        [r10], r11
	jmp short  .findNull

.epilogue:
	ret                               ; pop return address from stack and jump there
