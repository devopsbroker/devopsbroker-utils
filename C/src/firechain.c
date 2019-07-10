/*
 * firechain.c - DevOpsBroker utility for modifying iptables/ip6tables firewall chain rules
 *
 * Copyright (C) 2019 Edward Smith <edwardsmith@devopsbroker.org>
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
 * Developed on Ubuntu 18.04.2 LTS running kernel.osrelease = 4.18.0-16
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "org/devopsbroker/adt/listarray.h"
#include "org/devopsbroker/io/shell.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/memory.h"
#include "org/devopsbroker/lang/string.h"
#include "org/devopsbroker/lang/stringbuilder.h"
#include "org/devopsbroker/terminal/ansi.h"
#include "org/devopsbroker/terminal/commandline.h"
#include "org/devopsbroker/text/linebuffer.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define END_OF_FILE 0

#define USAGE_MSG "firechain " ANSI_GOLD "[help]" ANSI_YELLOW " { add | delete | view } " ANSI_GOLD "[OPTION...]"

#define ADD_USAGE_MSG "firechain add { raw | mangle | nat | filter } CHAIN_NAME { tcp | udp } { " ANSI_GOLD "[multi]" ANSI_YELLOW " source | dest } PORT_NUM ACTION"

#define DELETE_USAGE_MSG "firechain delete { raw | mangle | nat | filter } CHAIN_NAME { tcp | udp } { " ANSI_GOLD "[multi]" ANSI_YELLOW " source | dest } PORT_NUM"

#define VIEW_USAGE_MSG "firechain view { raw | mangle | nat | filter } CHAIN_NAME"

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef enum FirewallAction {
	ADD = 0,
	UPDATE,
	DELETE,
	VIEW
} FirewallAction;

typedef enum Protocol {
	TCP = 0,
	UDP
} Protocol;

typedef enum PortType {
	SOURCE = 0,
	DESTINATION,
	MULTIPORT
} PortType;

typedef struct FirewallParams {
	char *tableName;
	char *chainName;
	char *ruleAction;
	FirewallAction action;
	Protocol protocol;
	PortType portType;
	int portNumber;
	ListArray ruleList;
} FirewallParams;

static_assert(sizeof(FirewallParams) == 56, "Check your assumptions");

// ═════════════════════════════ Global Variables ═════════════════════════════


// ════════════════════════════ Function Prototypes ═══════════════════════════

static int processAdd(FirewallParams *firewallParams);

static int processDelete(FirewallParams *firewallParams);

static int findRuleIndex(FirewallParams *firewallParams);

static void printHelp(int argc, char *argv[]);

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Possible command-line options:
 *
 *   -d -> Download speed
 *   -u -> Upload speed
 *   -s -> Speed
 *   -l -> Acceptable latency
 *   -g -> Generate tuning script
 *   -h -> Help
 * ----------------------------------------------------------------------------
 */
static void processCmdLine(CmdLineParam *cmdLineParm, FirewallParams *firewallParams) {
	StringBuilder strBuilder;
	int argIndex = 1;

	// Perform initializations
	f668c4bd_meminit(firewallParams, sizeof(FirewallParams));

	// ----------------------- Determine firewall action -----------------------

	if (d7ad7024_isEqual(cmdLineParm, "add", argIndex)) {
		firewallParams->action = ADD;
	} else if (d7ad7024_isEqual(cmdLineParm, "delete", argIndex)) {
		firewallParams->action = DELETE;
	} else if (d7ad7024_isEqual(cmdLineParm, "view", argIndex)) {
		firewallParams->action = VIEW;
	} else {
		c7c88e52_invalidValue("action", cmdLineParm->argv[argIndex]);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	argIndex++;

	// ------------------------ Determine firewall table -----------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("table name");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	if (d7ad7024_isEqual(cmdLineParm, "raw", argIndex) || d7ad7024_isEqual(cmdLineParm, "mangle", argIndex)
		|| d7ad7024_isEqual(cmdLineParm, "nat", argIndex) || d7ad7024_isEqual(cmdLineParm, "filter", argIndex)) {
		firewallParams->tableName = cmdLineParm->argv[argIndex];
	} else {
		c7c88e52_invalidValue("table name", cmdLineParm->argv[argIndex]);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	argIndex++;

	// -------------------------- Firewall chain name --------------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("chain name");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	firewallParams->chainName = cmdLineParm->argv[argIndex];

	// Initialize the LineBuffer
	String *line = NULL;
	LineBuffer lineBuffer;
	c196bc72_initLineBuffer(&lineBuffer);

	// Initialize the ListArray
	b196167f_initListArray(&firewallParams->ruleList);

	// Build the iptables command-line
	c598a24c_initStringBuilder(&strBuilder);
	c598a24c_append_string(&strBuilder, "/sbin/iptables -t ");
	c598a24c_append_string(&strBuilder, firewallParams->tableName);
	c598a24c_append_string(&strBuilder, " --line-numbers --numeric --list ");
	c598a24c_append_string(&strBuilder, firewallParams->chainName);
	c598a24c_append_string(&strBuilder, " 2>/dev/null");

	Shell iptables;

	f6843e7e_openShellForRead(&iptables, strBuilder.buffer);

	char *rule;
	int numBytes = c196bc72_populateLineBuffer(&lineBuffer, iptables.fd);
	while (numBytes != END_OF_FILE) {
		line = c196bc72_getLine(&lineBuffer);

		while (line != NULL) {
			rule = f668c4bd_malloc(line->length + 1);
			f6215943_copyToBuffer(line->value, rule, line->length);
			b196167f_add(&firewallParams->ruleList, rule);

			line = c196bc72_getLine(&lineBuffer);
		}

		numBytes = c196bc72_populateLineBuffer(&lineBuffer, iptables.fd);
	}
	f6843e7e_closeShell(&iptables);

	if (firewallParams->ruleList.length == 0) {
		c7c88e52_invalidValue("chain name", firewallParams->chainName);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	argIndex++;

	if (firewallParams->action == VIEW) {
		return;
	}

	// -------------------------- Determine protocol ---------------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("protocol");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	if (d7ad7024_isEqual(cmdLineParm, "tcp", argIndex)) {
		firewallParams->protocol = TCP;
	} else if (d7ad7024_isEqual(cmdLineParm, "udp", argIndex)) {
		firewallParams->protocol = UDP;
	} else {
		c7c88e52_invalidValue("protocol", cmdLineParm->argv[argIndex]);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	argIndex++;

	// -------------------------- Determine port type --------------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("port type");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	bool isMultiPort = false;

	// The multiport designation is optional
	if (d7ad7024_isEqual(cmdLineParm, "multi", argIndex)) {
		isMultiPort = true;
		argIndex++;

		if (cmdLineParm->argc == argIndex) {
			c7c88e52_missingParam("port type");
			c7c88e52_printUsage(USAGE_MSG);
			exit(EXIT_FAILURE);
		}
	}

	if (d7ad7024_isEqual(cmdLineParm, "source", argIndex)) {
		firewallParams->portType = SOURCE;
	} else if (d7ad7024_isEqual(cmdLineParm, "dest", argIndex)) {
		firewallParams->portType = DESTINATION;
	} else {
		c7c88e52_invalidValue("port type", cmdLineParm->argv[argIndex]);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	// Bitwise OR in the MULTIPORT bit if specified
	if (isMultiPort) {
		firewallParams->portType |= MULTIPORT;
	}

	argIndex++;

	// ------------------------------ Port number ------------------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("port number");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	firewallParams->portNumber = d7ad7024_getUint32(cmdLineParm, "port number", argIndex);

	// TODO: Need a range validation method
	if (firewallParams->portNumber == 0 || firewallParams->portNumber > 65535) {
		c7c88e52_invalidValue("port number", cmdLineParm->argv[argIndex]);
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	argIndex++;

	if (firewallParams->action == DELETE) {
		return;
	}

	// ------------------------------ Rule action ------------------------------

	if (cmdLineParm->argc == argIndex) {
		c7c88e52_missingParam("rule action");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}

	firewallParams->ruleAction = cmdLineParm->argv[argIndex];
}

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "firechain";
	c7c88e52_ensureUserIsRoot();

	if (argc == 1) {
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	} else if (f6215943_isEqual("help", argv[1])) {
		printHelp(argc, argv);
		exit(EXIT_SUCCESS);
	}

	FirewallParams firewallParams;
	CmdLineParam cmdLineParm;

	d7ad7024_initCmdLineParam(&cmdLineParm, argc, argv, USAGE_MSG);
	processCmdLine(&cmdLineParm, &firewallParams);

	if (firewallParams.action == ADD) {
		processAdd(&firewallParams);
	} else if (firewallParams.action == DELETE) {
		processDelete(&firewallParams);
	} else if (firewallParams.action == VIEW) {
		for (int i=0; i < firewallParams.ruleList.length; i++) {
			puts(firewallParams.ruleList.values[i]);
		}
	}

	b196167f_destroyAllElements(&firewallParams.ruleList);

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

static int findRuleIndex(FirewallParams *firewallParams) {
	StringBuilder strBuilder;

	c598a24c_initStringBuilder(&strBuilder);

	// Search for existing rule in table chain
	if ((firewallParams->portType & MULTIPORT) > 0) {

	} else {
		if (firewallParams->protocol == TCP) {
			c598a24c_append_string(&strBuilder, "tcp ");
		} else {
			c598a24c_append_string(&strBuilder, "udp ");
		}

		if (firewallParams->portType == SOURCE) {
			c598a24c_append_string(&strBuilder, "spt:");
		} else {
			c598a24c_append_string(&strBuilder, "dpt:");
		}

		c598a24c_append_int(&strBuilder, firewallParams->portNumber);
	}

	for (int i=2; i < firewallParams->ruleList.length; i++) {
		if (f6215943_search(strBuilder.buffer, firewallParams->ruleList.values[i])) {
			return i;
		}
	}

	// Rule not found
	return -1;
}

static int processAdd(FirewallParams *firewallParams) {
	StringBuilder strBuilder;
	int ruleIndex = findRuleIndex(firewallParams);
	int status = 0;

	// Insert the iptables firewall rule if it does not already exist
	if (ruleIndex < 0) {
		c598a24c_initStringBuilder(&strBuilder);

		// Build the iptables command-line
		c598a24c_append_string(&strBuilder, "/sbin/iptables -t ");
		c598a24c_append_string(&strBuilder, firewallParams->tableName);
		c598a24c_append_string(&strBuilder, " -I ");
		c598a24c_append_string(&strBuilder, firewallParams->chainName);
		c598a24c_append_char(&strBuilder, ' ');
		c598a24c_append_uint(&strBuilder, firewallParams->ruleList.length - 2);
		c598a24c_append_string(&strBuilder, " -p ");

		if (firewallParams->protocol == TCP) {
			c598a24c_append_string(&strBuilder, "tcp");
		} else {
			c598a24c_append_string(&strBuilder, "udp");
		}

		c598a24c_append_string(&strBuilder, " -m ");

		if (firewallParams->protocol == TCP) {
			c598a24c_append_string(&strBuilder, "tcp");
		} else {
			c598a24c_append_string(&strBuilder, "udp");
		}

		if (firewallParams->portType == SOURCE) {
			c598a24c_append_string(&strBuilder, " --sport ");
		} else {
			c598a24c_append_string(&strBuilder, " --dport ");
		}

		c598a24c_append_int(&strBuilder, firewallParams->portNumber);

		c598a24c_append_string(&strBuilder, " -j ");
		c598a24c_append_string(&strBuilder, firewallParams->ruleAction);

		// Insert the iptables firewall rule
		status = system(strBuilder.buffer);
	} else {
		c7c88e52_printNotice("Rule already exists");
	}

	return status;
}

static int processDelete(FirewallParams *firewallParams) {
	StringBuilder strBuilder;
	int ruleIndex = findRuleIndex(firewallParams);
	int status = 0;

	// Delete the iptables firewall rule if it exists
	if (ruleIndex >= 0) {
		c598a24c_initStringBuilder(&strBuilder);

		// Build the iptables command-line
		c598a24c_append_string(&strBuilder, "/sbin/iptables -t ");
		c598a24c_append_string(&strBuilder, firewallParams->tableName);
		c598a24c_append_string(&strBuilder, " -D ");
		c598a24c_append_string(&strBuilder, firewallParams->chainName);
		c598a24c_append_char(&strBuilder, ' ');
		c598a24c_append_int(&strBuilder, ruleIndex);

		// Delete the iptables firewall rule
		status = system(strBuilder.buffer);
	} else {
		c7c88e52_printNotice("Rule does not exist");
	}

	return status;
}

static void printHelp(int argc, char *argv[]) {
	if (argc == 2) {
		c7c88e52_printUsage(USAGE_MSG);

		puts("\nManage iptables firewall chain rules");

		puts(ANSI_BOLD "\nValid Actions:" ANSI_RESET);
		puts(ANSI_BOLD "  add\t\t" ANSI_YELLOW "Adds an iptables firewall rule to an existing chain" ANSI_RESET);
		puts(ANSI_BOLD "  delete\t" ANSI_YELLOW "Deletes an iptables firewall rule from an existing chain" ANSI_RESET);
		puts(ANSI_BOLD "  view\t\t" ANSI_YELLOW "View all of the rules in a given chain" ANSI_RESET);
	} else {
		if (f6215943_isEqual("add", argv[2])) {
			c7c88e52_printUsage(ADD_USAGE_MSG);

			puts(ANSI_ROMANTIC "\nAdds an iptables firewall rule to an existing chain" ANSI_RESET);
		} else if (f6215943_isEqual("delete", argv[2])) {
			c7c88e52_printUsage(DELETE_USAGE_MSG);

			puts(ANSI_ROMANTIC "\nDeletes an iptables firewall rule from an existing chain" ANSI_RESET);
		} else if (f6215943_isEqual("view", argv[2])) {
			c7c88e52_printUsage(VIEW_USAGE_MSG);

			puts(ANSI_ROMANTIC "\nView all of the rules in a given chain" ANSI_RESET);
		} else {
			c7c88e52_invalidValue("action", argv[2]);
			c7c88e52_printUsage(USAGE_MSG);
			exit(EXIT_FAILURE);
		}
	}
}
