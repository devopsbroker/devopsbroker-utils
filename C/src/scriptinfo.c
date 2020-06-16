/*
 * scriptinfo.c - DevOpsBroker C source file for providing Bash script information
 *
 * Copyright (C) 2018-2020 Edward Smith <edwardsmith@devopsbroker.org>
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
 * Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-29
 *
 * Emits values for the SCRIPT_DIR and SCRIPT_EXEC Bash variables.
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <errno.h>

#include <sys/stat.h>
#include <limits.h>
#include <unistd.h>

#include "org/devopsbroker/io/file.h"
#include "org/devopsbroker/lang/error.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define USAGE_MSG "scriptinfo SCRIPT_NAME"

// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ════════════════════════════════ Structures ════════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

char *f67f16c0_getScriptName(char *pathName);

// ═════════════════════════════ Global Variables ═════════════════════════════


// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "scriptinfo";

	if (argc == 1) {
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	if (argv[1][0] == '\0') {
		c7c88e52_missingParam("script name");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	char *pathName = argv[1];
	char *realPathName = NULL;
	char *scriptDir = NULL;
	char *scriptExec = NULL;

	// Stat the script
	FileStatus fileStatus;
	e2f74138_getLinkStatus(pathName, &fileStatus);

	// Handle symbolic links
	if (S_ISLNK(fileStatus.st_mode)) {
		realPathName = e2f74138_readlink(pathName, fileStatus.st_size);

		scriptDir = realPathName;
		f67f16c0_getScriptName(realPathName);
		scriptExec = f67f16c0_getScriptName(pathName);

	// Handle regular files
	} else if (S_ISREG(fileStatus.st_mode)) {
		realPathName = e2f74138_realpath(pathName);

		scriptDir = realPathName;
		scriptExec = f67f16c0_getScriptName(realPathName);
	}

	// Cannot set environment variables in parent shell from binary executable
	puts(scriptDir);
	puts(scriptExec);

	if (realPathName != NULL) {
		free(realPathName);
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════
