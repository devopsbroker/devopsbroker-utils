/*
 * verifyclass.c - DevOpsBroker utility for validating Java-like fully-qualified class names
 *
 * Copyright (C) 2018 Edward Smith <edwardsmith@devopsbroker.org>
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
 * Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-36
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdlib.h>

#include "org/devopsbroker/lang/error.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════


// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ═════════════════════════════ Global Variables ═════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════


// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {
	if (argc < 2) {
		c7c88e52_printUsage("verifyclass com.example.foo.Bar");
		exit(EXIT_FAILURE);
	}

	// Classname parameter
	register const char *classname = argv[1];
	register char ch = *classname;
	register int domainNameLength;

	while (ch >= 'a' && ch <= 'z') {
		ch = *(++classname);
	}

	while (ch == '.') {
		if (*(classname-1) == '-') {
			exit(EXIT_FAILURE);
		}

		ch = *(++classname);

		if (ch >= 'A' && ch <= 'Z') {
			do {
				ch = *(++classname) | 0x20;
			} while ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9'));

			if (ch == ' ') {
				// Exit with success
				exit(EXIT_SUCCESS);
			}

			exit(EXIT_FAILURE);
		}

		if (ch == '-') {
			exit(EXIT_FAILURE);
		}

		domainNameLength = 0;
		while ((ch >= 'a' && ch <= 'z') || (ch >= '0' && ch <= '9') || ch == '-') {
			if (++domainNameLength > 63) {
				exit(EXIT_FAILURE);
			}

			ch = *(++classname);
		}

		if (domainNameLength < 2) {
			exit(EXIT_FAILURE);
		}
	}

	// Exit with failure
	exit(EXIT_FAILURE);
}

// ═════════════════════════ Function Implementations ═════════════════════════
