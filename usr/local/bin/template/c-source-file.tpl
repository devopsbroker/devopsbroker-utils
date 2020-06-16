#!/usr/bin/bash

#
# c-source-file.tpl - DevOpsBroker template script for generating C source files
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
# Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-45
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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

## Variables
YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no source file name parameter specified
if [ -z "$sourceFileName" ]; then
	printUsage "c-source-file.tpl file.c"
	exit 1
fi

# Display error and usage if invalid source file name specified
if [[ "$sourceFileName" != *.c ]]; then
	printError "c-source-file.tpl" "Invalid C source file name: '$sourceFileName'"
	echo
	printUsage "c-source-file.tpl file.c"

	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Derive the header file name from the source file name
headerFileName=${sourceFileName/.c/.h}

## Template
/usr/bin/cat << EOF
/*
 * $sourceFileName - C source file
 *
 * Copyright (C) $YEAR AUTHOR_NAME <email@address.com>
 *
 * This program is free software: you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation, either version 3 of the License, or (at your option) any later
 * version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
 * details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * -----------------------------------------------------------------------------
 * Developed on $(getUbuntuRelease) running kernel.osrelease = $(getKernelVersion)
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>
#include <stdlib.h>

#include <locale.h>

#include "$headerFileName"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════


// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ═════════════════════════════ Global Variables ═════════════════════════════


// ════════════════════════════ Function Prototypes ═══════════════════════════


// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	// For a list of all supported locales, try "locale -a" from the command-line
	setlocale(LC_ALL, "C.UTF-8");

	for (int i=0; i < argc; i++) {
		printf("%s\n", argv[i]);
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════


EOF
