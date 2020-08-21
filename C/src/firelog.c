/*
 * firelog.c - DevOpsBroker utility for parsing and filtering firewall logs
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
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _GNU_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <locale.h>

#include "org/devopsbroker/adt/listarray.h"
#include "org/devopsbroker/io/async.h"
#include "org/devopsbroker/io/filebuffer.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/log/logline.h"
#include "org/devopsbroker/memory/memorypool.h"
#include "org/devopsbroker/memory/pagepool.h"
#include "org/devopsbroker/memory/slabpool.h"
#include "org/devopsbroker/text/linebuffer.h"
#include "org/devopsbroker/text/regex.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define END_OF_FILE   0

// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

static void initSyslog(AIOContext *aioContext, AIOFile *aioFile, FileBufferList *fileBufferList);
static void cleanUpSyslog(AIOFile *aioFile, FileBufferList *fileBufferList);

static void filterInputLogLine(LogLine *logLine);
static void filterOutputLogLine(LogLine *logLine);

// ═════════════════════════════ Global Variables ═════════════════════════════

// Input/Output LogLine ListArrays
ListArray *inputLogLineList;
ListArray *outputLogLineList;

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {
	AIOContext     aioContext;
	AIOFile        aioFile;
	FileBufferList fileBufferList;
	FileBuffer    *fileBuffer;
	int64_t        dataLength;
	Line           syslogLine;
	Line          *linePtr = NULL;

	// For a list of all supported locales, try "locale -a" from the command-line
	setlocale(LC_ALL, "C.UTF-8");

	programName = "firelog";

	// Create the default LogLine and Input/Output LogLine ListArrays
	LogLine logLine;
	inputLogLineList = b196167f_createListArray();
	outputLogLineList = b196167f_createListArray();

	// Compile the BLOCK header regular expression
	regex_t regExpr;
	b395ed5f_compileRegExpr(&regExpr, "\\[.* BLOCK\\] ", REG_EXTENDED);

	// Initialize the syslog file handling
	initSyslog(&aioContext, &aioFile, &fileBufferList);

	// Process /var/log/syslog file
	dataLength = aioFile.fileSize;

	while (dataLength > 0) {
		ce97d170_readFileBufferList(&aioFile, &fileBufferList, dataLength);
		fileBuffer = fileBufferList.values[0];

		while (fileBuffer != NULL) {
			dataLength -= fileBuffer->numBytes;
			linePtr = c196bc72_getLineFromFileBuffer(&syslogLine, fileBuffer);

			while (linePtr != NULL) {
				fileBuffer->dataOffset += (linePtr->length + 1);

				// Check for a firewall BLOCK header
				if (b395ed5f_matchRegExpr(&regExpr, linePtr->value, 0)) {
					b45c9f7e_initLogLine(&logLine, linePtr);

					if (*logLine.in) {
						filterInputLogLine(&logLine);
					} else {
						filterOutputLogLine(&logLine);
					}
				}

				linePtr = c196bc72_getLineFromFileBuffer(&syslogLine, fileBuffer);
			}

			fileBuffer = fileBuffer->next;

			if (fileBuffer == NULL)  {
				ce97d170_resetFileBufferList(&fileBufferList, f502a409_releasePage);
			}
		}
	}

	// Clean up the AIOContext
	f1207515_cleanUpAIOContext(&aioContext);
	cleanUpSyslog(&aioFile, &fileBufferList);
	b86b2c8d_destroyMemoryPool(false);
	f502a409_destroyPagePool(false);
	b426145b_destroySlabPool(false);

	// Free memory allocated for the regular expression
	b395ed5f_freeRegExpr(&regExpr);

	register uint32_t listLength;
	register void **listValues;
	register uint32_t i;
	register LogLine *listEntry;

	// Process the inputLogLineList entries
	if (inputLogLineList->length > 0) {
		listLength = inputLogLineList->length;
		listValues = inputLogLineList->values;
		i = 0;

		d99c60f5_printBox("firelog INPUT BLOCK Log Entries", false);

		// Loop over the inputLogLineList entries and free the LogLine buffers and instances
		while (i < listLength) {
			listEntry = listValues[i++];

			if (listEntry->destPort == 0) {
				// Print ICMP firewall entry
				printf("Count: %u IN=%s MAC=%s SRC=%s DST=%s PROTO=%s TYPE=%u\n", listEntry->count, listEntry->in, listEntry->macAddress, \
					listEntry->sourceIPAddr, listEntry->destIPAddr, listEntry->protocol, listEntry->sourcePort);
			} else {
				// Print non-ICMP firewall entry
				printf("Count: %u IN=%s MAC=%s SRC=%s DST=%s PROTO=%s SPT=%u DPT=%u\n", listEntry->count, listEntry->in, listEntry->macAddress, \
					listEntry->sourceIPAddr, listEntry->destIPAddr, listEntry->protocol, listEntry->sourcePort, listEntry->destPort);
			}

			b45c9f7e_destroyLogLine(listEntry);
		}

		b196167f_destroyListArray(inputLogLineList, NULL);
		printf("\n");
	}

	fflush(stdout);

	// Process the outputLogLineList entries
	if (outputLogLineList->length > 0) {
		listLength = outputLogLineList->length;
		listValues = outputLogLineList->values;
		i = 0;

		d99c60f5_printBox("firelog OUTPUT BLOCK Log Entries", false);

		// Loop over the outputLogLineList entries and free the LogLine buffers and instances
		while (i < listLength) {
			listEntry = listValues[i++];

			printf("Count: %u OUT=%s SRC=%s DST=%s PROTO=%s SPT=%u DPT=%u\n", listEntry->count, listEntry->out, listEntry->sourceIPAddr, \
				 listEntry->destIPAddr, listEntry->protocol, listEntry->sourcePort, listEntry->destPort);

			b45c9f7e_destroyLogLine(listEntry);
		}

		b196167f_destroyListArray(outputLogLineList, NULL);
		printf("\n");
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

void initSyslog(AIOContext *aioContext, AIOFile *aioFile, FileBufferList *fileBufferList) {
	FileStatus fileStatus;

	// 1. Initialize the FileBufferList struct
	ce97d170_initFileBufferList(fileBufferList);

	// 2. Initialize the AIOContext
	f1207515_initAIOContext(aioContext, 8);

	// 3. Initialize the AIOFile struct
	f1207515_initAIOFile(aioContext, aioFile, "/var/log/syslog");

	// 4. Open the file
	f1207515_open(aioFile, FOPEN_READONLY, 0);

	// 5. Retrieve the file size
	e2f74138_getDescriptorStatus(aioFile->fd, &fileStatus);
	aioFile->fileSize = fileStatus.st_size;
}

static void cleanUpSyslog(AIOFile *aioFile, FileBufferList *fileBufferList) {
	// 1. Close the file
	f1207515_cleanUpAIOFile(aioFile);

	// 2. Clean up the FileBufferList struct
	ce97d170_cleanUpFileBufferList(fileBufferList, f502a409_releasePage);
}

/*
 * IN=enp4s0 OUT= MAC=ff:ff:ff:ff:ff:ff:aa:bb:cc:dd:ee:ff:11:00 SRC=192.168.1.110 DST=192.168.1.255 PROTO=UDP SPT=59391 DPT=15600
 *
 * If an input rule triggered:
 *   o Use MAC Address filtering
 *   o Ignore changes in SRC
 *   o Ignore changes in SPT and/or DPT
 */
void filterInputLogLine(register LogLine *logLine) {
	register const uint32_t listLength = inputLogLineList->length;
	register void **listValues = inputLogLineList->values;
	register uint32_t i = 0;
	register LogLine *listEntry;

	// 1. Loop over the existing inputLogLineList entries
	while (i < listLength) {
		listEntry = listValues[i++];

		if (f6215943_isEqual(listEntry->in, logLine->in)
			&& f6215943_isEqual(listEntry->out, logLine->out)
			&& f6215943_isEqual(listEntry->macAddress, logLine->macAddress)
			&& f6215943_isEqual(listEntry->sourceIPAddr, logLine->sourceIPAddr)
			&& f6215943_isEqual(listEntry->protocol, logLine->protocol)) {

			if (listEntry->sourcePort == logLine->sourcePort
				|| listEntry->destPort == logLine->destPort) {

				listEntry->count++;
				return;
			}
		}
	}

	// 2. Add LogLine to the inputLogLineList
	LogLine *newListItem = b45c9f7e_cloneLogLine(logLine);
	b196167f_add(inputLogLineList, newListItem);
}

/*
 * IN= OUT=enp4s0 SRC=2001:db8:85a3:8d3:1319:8a2e:370:7348 DST=2607:f8b0:4003:0c0c:0000:0000:0000:007f PROTO=UDP SPT=45771 DPT=19302
 *
 * If an output rule triggered:
 *   o Ignore changes in SPT
 */
void filterOutputLogLine(register LogLine *logLine) {
	register const uint32_t listLength = outputLogLineList->length;
	register void **listValues = outputLogLineList->values;
	register uint32_t i = 0;
	register LogLine *listEntry;

	// 1. Loop over the existing outputLogLineList entries
	while (i < listLength) {
		listEntry = listValues[i++];

		if (f6215943_isEqual(listEntry->in, logLine->in)
			&& f6215943_isEqual(listEntry->out, logLine->out)
			&& f6215943_isEqual(listEntry->destIPAddr, logLine->destIPAddr)
			&& f6215943_isEqual(listEntry->protocol, logLine->protocol)
			&& listEntry->destPort == logLine->destPort) {

			listEntry->count++;
			return;
		}
	}

	// 2. Add LogLine to the outputLogLineList
	LogLine *newListItem = b45c9f7e_cloneLogLine(logLine);
	b196167f_add(outputLogLineList, newListItem);
}
