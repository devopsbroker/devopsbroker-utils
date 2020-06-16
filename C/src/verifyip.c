/*
 * verifyip.c - DevOpsBroker utility for validating IPv4 or IPv6 addresses
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
 * ----------------------------------------------------------------------------
 * Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-43
 *
 * https://en.wikipedia.org/wiki/IPv6_address
 *   o IPv6 address is represented as eight groups of four hexadecimal digits
 *   o Groups are separated by colons (:)
 *   o Hexadecimal digits are case-insensitive
 *   o Leading zeroes in a group may be omitted, but each group must retain at
 *     least one hexadecimal digit
 *   o One or more consecutive groups containing zeros only may be replaced
 *     with a single empty group, using two consecutive colons (::) This
 *     substitution may only be applied once to avoid ambiguity
 *   o Supports the special IPv4-mapped notation ::ffff:192.0.2.128
 *   o (::) is not used to shorten just a single 0 field
 *
 * TODO: Read from stdin
 * ----------------------------------------------------------------------------
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/net/ip-util.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════


// ═════════════════════════════════ Typedefs ═════════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

void c009cdda_verifyIPv4(char *ipAddress);
void c009cdda_verifyIPv6(char *ipAddress);

// ═════════════════════════════ Global Variables ═════════════════════════════


// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {
	if (argc < 2) {
		c7c88e52_printUsage("verifyip IP_ADDR");
		exit(EXIT_FAILURE);
	}

	// IP Address parameter
	char *ip = argv[1];
	int ipType = a25c96b2_detectIPType(ip);

	if (ipType == 4) {
		c009cdda_verifyIPv4(ip);
	} else if (ipType == 6) {
		c009cdda_verifyIPv6(ip);
	} else {
		exit(EXIT_FAILURE);
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════
