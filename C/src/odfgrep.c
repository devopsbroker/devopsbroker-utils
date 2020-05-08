/*
 * odfgrep.c - DevOpsBroker utility for searching OpenDocument Format files
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
 * Developed on Ubuntu 18.04.4 LTS running kernel.osrelease = 5.3.0-28
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _GNU_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>
#include <stdbool.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <assert.h>
#include <pthread.h>

#include "org/devopsbroker/adt/unsignedintarray.h"
#include "org/devopsbroker/compress/ziparchive.h"
#include "org/devopsbroker/fs/directory.h"
#include "org/devopsbroker/io/async.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/string.h"
#include "org/devopsbroker/lang/stringbuilder.h"
#include "org/devopsbroker/memory/pagepool.h"
#include "org/devopsbroker/system/linux.h"
#include "org/devopsbroker/terminal/commandline.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define USAGE_MSG "odfgrep " ANSI_GOLD "{ -d | -h }" ANSI_YELLOW " PATTERN " ANSI_GOLD "[FILE...]"

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef struct SearchParams {
	char*    directory;
	char*    pattern;
	char**   filenameList;
	uint32_t filenameListLength;
} SearchParams;

static_assert(sizeof(SearchParams) == 32, "Check your assumptions");

// ═════════════════════════════ Global Variables ═════════════════════════════


// ════════════════════════════ Function Prototypes ═══════════════════════════

static void processODFFile(AIOContext *aioContext, char *filename);

static bool findODFFiles(char *filename);

static void printHelp();

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Possible command-line options:
 *
 *   -d -> The directory to search
 *   -h -> Help
 * ----------------------------------------------------------------------------
 */
static void processCmdLine(CmdLineParam *cmdLineParm, SearchParams *searchParams);

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "odfgrep";

	SearchParams searchParams;
	CmdLineParam cmdLineParm;

	d7ad7024_initCmdLineParam(&cmdLineParm, argc, argv, USAGE_MSG);
	processCmdLine(&cmdLineParm, &searchParams);

	// 1. List the contents of the current directory
	FilePathList filePathList;
	DirPath dirPath;

	d0059b5b_initDirPath(&dirPath, searchParams.directory);
	d0059b5b_initFilePathList(&filePathList);
	d0059b5b_find(&filePathList, &dirPath, findODFFiles);

	if (filePathList.length > 0) {
		AIOContext aioContext;
		char *filename;

		f1207515_initAIOContext(&aioContext, 16);

		for (uint32_t i=0; i < filePathList.length; i++) {
			filename = filePathList.values[i];
			processODFFile(&aioContext, filename);
		}

		f1207515_printContext(&aioContext);
		f1207515_cleanUpAIOContext(&aioContext);
	}

	d0059b5b_cleanUpDirPath(&dirPath);
	d0059b5b_cleanUpFilePathList(&filePathList);
	f502a409_destroyPagePool(true);

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

static void processODFFile(AIOContext *aioContext, char *filename) {
	ZipArchive zipArchive;

	// 1. Initialize ZipArchive
	ce667b0d_initZipArchive(&zipArchive, aioContext, filename);
	zipArchive.outputDir = "/tmp/unzip/";

	ce667b0d_unzip(&zipArchive);

	ce667b0d_cleanUpZipArchive(&zipArchive);
}

static bool findODFFiles(char *filename) {
	char *extension = f6215943_findLastChar(filename, '.');

	return (extension != NULL
			&& extension != filename
			&& extension[1] == 'o'
			&& extension[2] == 'd'
			&& (extension[3] == 't' || extension[3] == 's' || extension[3] == 'p'));
}

static void processCmdLine(CmdLineParam *cmdLineParm, SearchParams *searchParams) {
	register int argc = cmdLineParm->argc;
	register char **argv = cmdLineParm->argv;

	// Perform initializations
	f668c4bd_meminit(searchParams, sizeof(SearchParams));

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 'd') {
				searchParams->directory = argv[++i];
			} else if (argv[i][1] == 'h') {
				printHelp();
				exit(EXIT_SUCCESS);
			} else {
				c7c88e52_invalidOption(argv[i]);
				c7c88e52_printUsage(USAGE_MSG);
				exit(EXIT_FAILURE);
			}
		} else {
			// Extract the search pattern
			searchParams->pattern = argv[i];

			// Calculate how many files to search
			i++;
			if (i < argc) {
				searchParams->filenameList = &argv[i];
				searchParams->filenameListLength = argc - i;
				i = argc;
			}
		}
	}

	if (searchParams->pattern == NULL) {
		c7c88e52_missingParam("pattern");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	// Default to the current directory if none specified on command-line
	if (searchParams->directory == NULL) {
		searchParams->directory = ".";
	}
}

static void printHelp() {
	c7c88e52_printUsage(USAGE_MSG);

	puts("\nSearches OpenDocument Format files for the given pattern");

	puts(ANSI_BOLD "\nDefault Values:" ANSI_RESET);
	puts("  Non-recursive search\tSearches all ODF files in the current directory");

	puts(ANSI_BOLD "\nExamples:" ANSI_RESET);
	puts("  odfgrep \"foo bar\"");
	puts("  odfgrep -d ~/Documents covfefe");
	puts("  odfgrep \"xyz 123\" file1.odt");

	puts(ANSI_BOLD "\nValid Options:\n");
	puts(ANSI_YELLOW "  -d\t" ANSI_ROMANTIC "Specify the directory to search");
	puts(ANSI_BOLD ANSI_YELLOW "  -h\t" ANSI_ROMANTIC "Print this help message\n");
}
