#!/bin/bash

#
# c-enum-source.tpl - DevOpsBroker template script for generating C enum source files
#
# Copyright (C) 2018-2019 Edward Smith <edwardsmith@devopsbroker.org>
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
# Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-36
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

## Bash exec variables
EXEC_MD5SUM=/usr/bin/md5sum
EXEC_VERIFYCLASS=/usr/local/bin/verifyclass

## Options
enumName="$1"

## Variables
includeGuard=''
typedefName=''
md5Hash=''
filename=''
variableName=''

YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if enum name is missing
if [ -z "$enumName" ]; then
	printUsage 'c-enum-source.tpl com.example.foo.Bar'
	exit 1
fi

# Display error if enum name is invalid
if ! $EXEC_VERIFYCLASS "$enumName"; then
	printError 'c-enum-source.tpl' "Invalid C enum name: '$enumName'"
	echo
	printUsage 'c-enum-source.tpl com.example.foo.Bar'

	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Set the C header file include guard
includeGuard="${enumName//./_}"
includeGuard="${includeGuard^^}"

# Set the typedef name
typedefName="$(echo $enumName | $EXEC_GREP -Eo '([A-Z][a-zA-Z]+){1}$')"

# Set the md5hash of the include guard
md5Hash=$(echo $includeGuard | $EXEC_MD5SUM | $EXEC_CUT -c 25-32)

# Set the file name according to the typedef name
filename=${typedefName,,}

# Set the variable name according to the typedef name
variableName=${typedefName,}

## Template
/bin/cat << EOF > $filename.h
/*
 * $filename.h - C header file for the ${enumName} enum
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
 * -----------------------------------------------------------------------------
 * Developed on $(getUbuntuRelease) running kernel.osrelease = $(getKernelVersion)
 *
 * echo $includeGuard | md5sum | cut -c 25-32
 * -----------------------------------------------------------------------------
 */

#ifndef ${includeGuard}_H
#define ${includeGuard}_H

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define ${md5Hash}_NUM_VALUES 2

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef enum $typedefName {
	FOO = 0,
	BAR
} $typedefName;

// ═══════════════════════════ Function Declarations ══════════════════════════

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Function:    ${md5Hash}_get${typedefName}
 * Description: Returns the ${typedefName} associated with the char* string
 *
 * Parameters:
 *   source     The char* pointer to convert to an ${typedefName} value
 * Returns:     The associated ${typedefName} value
 * ----------------------------------------------------------------------------
 */
${typedefName} ${md5Hash}_get${typedefName}(const char *source);

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Function:    ${md5Hash}_toString${typedefName}
 * Description: Returns the char* string representation of the ${typedefName} value
 *
 * Parameters:
 *   ${variableName}	The ${typedefName} value to convert to a char* string
 * Returns:     The char* string representation of the ${typedefName} value
 * ----------------------------------------------------------------------------
 */
char *${md5Hash}_toString${typedefName}(const ${typedefName} ${variableName});

#endif /* ${includeGuard}_H */

EOF

/bin/cat << EOF > $filename.c
/*
 * $filename.c - C source file for the ${enumName} enum
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
 * -----------------------------------------------------------------------------
 * Developed on $(getUbuntuRelease) running kernel.osrelease = $(getKernelVersion)
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include "$filename.h"

// ═════════════════════════════ Global Variables ═════════════════════════════

char *${md5Hash}_stringList[] = { "Foo", "Bar" };

// ═════════════════════════ Function Implementations ═════════════════════════

${typedefName} ${md5Hash}_get${typedefName}(register const char *source) {
	// Find the appropriate ${typedefName}
	for (register int i = 0; i < ${md5Hash}_NUM_VALUES; i++) {

		// TODO: Put logic here to check for equality between source and ${md5Hash}_stringList items

	}

	// TODO: Put error logic here when no match is found

	exit(EXIT_FAILURE);
}

char *${md5Hash}_toString${typedefName}(const ${typedefName} ${variableName}) {
	return ${md5Hash}_stringList[${variableName}];
}

EOF

exit 0
