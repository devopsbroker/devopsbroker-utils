/*
 * md5hash.c - DevOpsBroker utility for generating MD5 hashes
 *
 * Copyright (C) 2020 Edward Smith <edwardsmith@devopsbroker.org>
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
 * Developed on Ubuntu 18.04.4 LTS running kernel.osrelease = 5.3.0-59
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _GNU_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>
#include <stdlib.h>

#include "org/devopsbroker/hash/md5.h"
#include "org/devopsbroker/io/async.h"
#include "org/devopsbroker/io/file.h"
#include "org/devopsbroker/io/filebuffer.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/memory.h"
#include "org/devopsbroker/lang/string.h"
#include "org/devopsbroker/memory/memorypool.h"
#include "org/devopsbroker/memory/pagepool.h"
#include "org/devopsbroker/memory/slabpool.h"
#include "org/devopsbroker/terminal/commandline.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define USAGE_MSG "md5hash " ANSI_GOLD "{ -n numRounds | -s salt | -h }" ANSI_YELLOW " [FILE]"

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef struct MD5Params {
	char    *fileName;
	char    *salt;
	uint32_t saltLength;
	uint32_t numRounds;
} MD5Params;

static_assert(sizeof(MD5Params) == 24, "Check your assumptions");

// ═════════════════════════════ Global Variables ═════════════════════════════


// ════════════════════════════ Function Prototypes ═══════════════════════════

static void processCmdLine(CmdLineParam *cmdLineParam, MD5Params *md5Params);

static void printHelp();

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {
	CmdLineParam cmdLineParam;
	MD5Params md5Params;

	programName = "md5hash";

	d7ad7024_initCmdLineParam(&cmdLineParam, argc, argv, USAGE_MSG);
	processCmdLine(&cmdLineParam, &md5Params);

	// Common variables
	uint32_t md5State[4];
	ssize_t numBytes;

	// Initialize MD5 state
	f1518caf_initMD5State(md5State);

	if (md5Params.fileName == NULL) {
		char buffer[MEMORY_PAGE_SIZE];

		numBytes = e2f74138_readFile(STDIN_FILENO, buffer, MEMORY_PAGE_SIZE, "STDIN");

		while (numBytes != END_OF_FILE) {
			if (numBytes == MEMORY_PAGE_SIZE) {
				f1518caf_md5Stream(md5State, buffer, numBytes);
			} else {
				if (md5Params.salt == NULL) {
					f1518caf_md5(md5State, buffer, numBytes);
				} else {
					f1518caf_md5WithSalt(md5State, (uint8_t*)md5Params.salt, md5Params.saltLength, buffer, numBytes);
				}
			}

			numBytes = e2f74138_readFile(STDIN_FILENO, buffer, MEMORY_PAGE_SIZE, "STDIN");
		}

	} else {
		AIOContext aioContext;
		AIOFile aioFile;
		FileBufferList fileBufferList;
		FileBuffer *fileBuffer;
		int64_t dataLength;

		// Initialize the AIOContext and AIOFile
		f1207515_initAIOContext(&aioContext, 16);
		f1207515_initAIOFile(&aioContext, &aioFile, md5Params.fileName);

		// Initialize the FileBufferList struct
		ce97d170_initFileBufferList(&fileBufferList);

		// Open the file
		f1207515_open(&aioFile, FOPEN_READONLY, 0);
		dataLength = aioFile.fileSize;

		while (dataLength != 0) {
			ce97d170_readFileBufferList(&aioFile, &fileBufferList, dataLength);
			fileBuffer = fileBufferList.values[0];

			while (fileBuffer != NULL) {
				dataLength -= fileBuffer->numBytes;

				if (dataLength == 0) {
					f1518caf_md5StreamEnd(md5State, fileBuffer->buffer, fileBuffer->numBytes, aioFile.fileSize);
				} else {
					f1518caf_md5Stream(md5State, fileBuffer->buffer, fileBuffer->numBytes);
				}

				fileBuffer = fileBuffer->next;
			}
		}

//		f1207515_printContext(&aioContext);

		f1207515_cleanUpAIOFile(&aioFile);
		f1207515_cleanUpAIOContext(&aioContext);
		ce97d170_cleanUpFileBufferList(&fileBufferList, f502a409_releasePage);
		b86b2c8d_destroyMemoryPool(false);
		f502a409_destroyPagePool(false);
		b426145b_destroySlabPool(false);
	}

	// Print the MD5 digest
	f1518caf_printMD5(md5State);
	printf("  %s\n", (md5Params.fileName == NULL) ? "-" : md5Params.fileName);

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Possible command-line options:
 *
 *   -n -> Number of Rounds
 *   -s -> Salt
 *   -h -> Help
 * ----------------------------------------------------------------------------
 */
static void processCmdLine(CmdLineParam *cmdLineParam, MD5Params *md5Params) {
	register int argc = cmdLineParam->argc;
	register char **argv = cmdLineParam->argv;

	// Perform initializations
	f668c4bd_meminit(md5Params, sizeof(MD5Params));

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 'n') {
				md5Params->numRounds = d7ad7024_getUint32(cmdLineParam, "number of rounds", i++);
			} else if (argv[i][1] == 's') {
				md5Params->salt = d7ad7024_getString(cmdLineParam, "salt", i++);
				md5Params->saltLength = f6215943_getLength(md5Params->salt);
			} else if (argv[i][1] == 'h') {
				printHelp();
				exit(EXIT_SUCCESS);
			} else {
				c7c88e52_invalidOption(argv[i]);
				c7c88e52_printUsage(USAGE_MSG);
				exit(EXIT_FAILURE);
			}
		} else {
			md5Params->fileName = argv[i];
		}
	}
}

static void printHelp() {
	c7c88e52_printUsage(USAGE_MSG);

	puts("\nCalculates the MD5 hash of either a file or STDIN");

	puts(ANSI_BOLD "\nExamples:" ANSI_RESET);
	puts("  md5hash -n 1234 foo.txt");
	puts("  echo mypassword | md5hash -s abcdefghijklmnop");

	puts(ANSI_BOLD "\nValid Options:\n");
	puts(ANSI_YELLOW "  -n\t" ANSI_ROMANTIC "Number of MD5 Rounds");
	puts(ANSI_BOLD ANSI_YELLOW "  -s\t" ANSI_ROMANTIC "Salt");
	puts(ANSI_BOLD ANSI_YELLOW "  -h\t" ANSI_ROMANTIC "Print this help message\n");
}
