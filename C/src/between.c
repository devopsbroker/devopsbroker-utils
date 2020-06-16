/*
 * between.c - DevOpsBroker utility for extracting the string in between the START and END parameters
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
 * Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-43
 *
 * Can either read from stdin or a file specified on the command-line.
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "org/devopsbroker/io/file.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/string.h"
#include "org/devopsbroker/lang/stringbuilder.h"
#include "org/devopsbroker/terminal/ansi.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════


// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

// Remove trailing newline and carriage return
static inline void removeNewline(char *endPtr) {
	do {
		*endPtr = '\0';
		endPtr--;
	} while (*endPtr == '\n' || *endPtr == '\r');
}

// ═════════════════════════════ Global Variables ═════════════════════════════

char *pathName = NULL;
char *startPtr = NULL;
char *endPtr = NULL;

StringBuilder *textBlock = NULL;

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "between";

	if (argc == 1) {
		c7c88e52_printUsage("between START END " ANSI_AQUA "[input-file]");
		exit(EXIT_FAILURE);
	}

	if (argv[1][0] == '\0') {
		c7c88e52_printError_string("START parameter is missing\n\n");
		c7c88e52_printUsage("between START END " ANSI_AQUA "[input-file]");
		exit(EXIT_FAILURE);
	}

	if (argc == 2 || argv[2][0] == '\0') {
		c7c88e52_printError_string("END parameter is missing\n\n");
		char *usageMessage = f6215943_concatenate("between ", argv[1], " END " ANSI_AQUA "[input-file]", NULL);
		c7c88e52_printUsage(usageMessage);
		free(usageMessage);
		exit(EXIT_FAILURE);
	}

	// File-related variables
	int fileDescriptor;
	ssize_t numBytes;

	if (argc > 3) {
		pathName = argv[3];
		fileDescriptor = e2f74138_openFile(pathName, O_RDONLY);
	} else {
		pathName = "STDIN";
		fileDescriptor = STDIN_FILENO;
	}

	char buffer[PHYSICAL_BLOCK_SIZE];

	numBytes = e2f74138_readFile(fileDescriptor, buffer, PHYSICAL_BLOCK_SIZE, pathName);
	while (numBytes != END_OF_FILE) {
		// We have not yet found the start of the substring
		if (startPtr == NULL) {
			startPtr = f6215943_search(argv[1], buffer);

			if (startPtr != NULL) {
				endPtr = strstr(startPtr, argv[2]);

				if (endPtr != NULL) {
					removeNewline(endPtr);
					if (startPtr != endPtr) {
						printf("%s\n", startPtr);
					}
					break;
				} else {
					// Copy text into StringBuilder from startPtr to end of buffer
					numBytes -= (startPtr - buffer);
					textBlock = c598a24c_createStringBuilder_uint32(numBytes << 1);
					c598a24c_append_string_uint32(textBlock, startPtr, numBytes);
				}
			}

		// Looking for the end of the substring
		} else {
			endPtr = strstr(buffer, argv[2]);

			if (endPtr != NULL) {
				removeNewline(endPtr);

				// Copy text into StringBuilder from start of buffer to endPtr
				numBytes -= (endPtr - buffer);
				c598a24c_append_string_uint32(textBlock, buffer, numBytes);
				printf("%s\n", textBlock->buffer);
				break;
			} else {
				// Copy all text into StringBuilder from buffer
				c598a24c_append_string_uint32(textBlock, buffer, numBytes);
			}
		}

		numBytes = e2f74138_readFile(fileDescriptor, buffer, PHYSICAL_BLOCK_SIZE, pathName);
	}

	// Close the file if not STDIN
	if (fileDescriptor != STDIN_FILENO) {
		e2f74138_closeFile(fileDescriptor, pathName);
	}

	// Clean up StringBuilder if allocated
	if (textBlock != NULL) {
		c598a24c_destroyStringBuilder(textBlock);
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════
