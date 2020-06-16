#!/usr/bin/bash

#
# asm-source-file.tpl - DevOpsBroker template script for generating NASM source files
#
# Copyright (C) 2018-2020 Edward Smith <edwardsmith@devopsbroker.org>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------------
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-38
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Load /etc/devops/ansi.conf if ANSI_CONFIG is unset
if [ -z "$ANSI_CONFIG" ] && [ -f /etc/devops/ansi.conf ]; then
	source /etc/devops/ansi.conf
fi

${ANSI_CONFIG?"[1;91mCannot load '/etc/devops/ansi.conf': No such file[0m"}

# Load /etc/devops/exec.conf if EXEC_CONFIG is unset
if [ -z "$EXEC_CONFIG" ] && [ -f /etc/devops/exec.conf ]; then
	source /etc/devops/exec.conf
fi

${EXEC_CONFIG?"[1;91mCannot load '/etc/devops/exec.conf': No such file[0m"}

# Load /etc/devops/functions.conf if FUNC_CONFIG is unset
if [ -z "$FUNC_CONFIG" ] && [ -f /etc/devops/functions.conf ]; then
	source /etc/devops/functions.conf
fi

${FUNC_CONFIG?"[1;91mCannot load '/etc/devops/functions.conf': No such file[0m"}

################################## Variables ##################################

## Options
sourceFileName="$1"
functionName=${2:-'main'}

## Variables
YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no parameters given
if [ -z "$sourceFileName" ]; then
	printUsage "asm-source-file.tpl file.asm ${gold}[FUNC_NAME]"
	exit 1
fi

# Display error if invalid source file name specified
if [[ "$sourceFileName" != *.asm ]]; then
	printError 'asm-source-file.tpl' "Invalid NASM source file name: '$sourceFileName'"
	echo
	printUsage "asm-source-file.tpl file.asm ${gold}[FUNC_NAME]"

	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/usr/bin/cat << EOF
;
; $sourceFileName - Description goes here
;
; Copyright (C) $YEAR AUTHOR_NAME <email@address.com>
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
; Developed on $(getUbuntuRelease) running kernel.osrelease = $(getKernelVersion)
;
; nasm -felf64 $sourceFileName
;
; When stack frames are omitted using -fomit-frame-pointer for GCC, the
; function implementation changes to:
;
;	sub       rsp, 8                 ; Re-align stack frame and reserve memory for local variables
;	; function code
;	add       rsp, 8
;	ret
;
; Call exit(0) system call on 64-bit Linux:
;
;	mov       rax, 60                ; system call for exit
;	xor       rdi, rdi               ; exit code 0
;	syscall                          ; invoke operating system to exit
;
; -----------------------------------------------------------------------------
;

; ════════════════════════════ Include Directives ════════════════════════════


; ═══════════════════════════════ Preprocessor ═══════════════════════════════


; ═════════════════════════════ Initialized Data ═════════════════════════════

section .data               ; DX directives

; ════════════════════════════ Uninitialized Data ════════════════════════════

section .bss                ; RESX directives

; ══════════════════════════════ Assembly Code ═══════════════════════════════

section .text               ; TEXT section

; ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ ${functionName} ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

	global  ${functionName}:function
${functionName}:

.prologue:                            ; functions typically have a prologue
;	push      rbp                     ; save the caller frame pointer on the stack
;	mov       rbp, rsp                ; set current frame pointer to stack pointer

.localVariables:

	; Assembly code goes here

.epilogue:                            ; functions typically have an epilogue
	xor       rax, rax                ; exit code 0
;	leave                             ; mov rsp, rbp / pop rbp
	ret                               ; pop return address from stack and jump there

EOF

exit 0
