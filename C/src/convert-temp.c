/*
 * convert-temp.c - DevOpsBroker utility for converting between temperature formats
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
 * Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-39
 *
 * NOTE: C enums do not have localized scope. They are as global as any other
 *       piece of crap in C.
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdio.h>

#include <float.h>

#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/string.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════


// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef enum TemperatureType {
	CELSIUS = 0x43,
	FAHRENHEIT = 0x46,
	KELVIN = 0x4B,
	INVALID_TEMPERATURE_TYPE
} TemperatureType;

// ═════════════════════════════ Global Variables ═════════════════════════════


// ════════════════════════════ Function Prototypes ═══════════════════════════

static TemperatureType getTemperatureType(char *argument);
extern float b9ac2bf7_convertTemperature(char *inputTemp, TemperatureType fromTempType, TemperatureType toTempType);

// Error Handling Functions
extern void b9ac2bf7_invalidTemperature(char *programName, char *temperature);
extern void b9ac2bf7_invalidTemperatureType(char *programName, char *tempType);
extern void b9ac2bf7_missingParameter(char *programName, char *paramName);
extern void b9ac2bf7_usageMessage(char *fromTempTypeStr, char *toTempTypeStr, TemperatureType fromTempType);

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {
	TemperatureType fromTempType;
	TemperatureType toTempType;
	char *toTempTypeStr;
	char *temperatureStr;
	float convertedTemp;
	int argIndex = 0;

	programName = argv[0];

	fromTempType = getTemperatureType(argv[argIndex++]);

	if (fromTempType == INVALID_TEMPERATURE_TYPE) {
		if (argc == 1) {
			c7c88e52_printUsage("Please use { celsius | fahrenheit | kelvin } to convert temperatures");
			exit(EXIT_FAILURE);
		}

		fromTempType = getTemperatureType(argv[1]);
		if (fromTempType == INVALID_TEMPERATURE_TYPE) {
			b9ac2bf7_invalidTemperatureType(programName, argv[1]);
			c7c88e52_printUsage("Please use { celsius | fahrenheit | kelvin } to convert temperatures");
			exit(EXIT_FAILURE);
		}

		programName = argv[1];
		argIndex++;
		argc--;
	}

	if (argc < 2) {
		b9ac2bf7_missingParameter(programName, "TEMP_TYPE");
		b9ac2bf7_usageMessage(programName, NULL, fromTempType);
		exit(EXIT_FAILURE);
	}

	toTempTypeStr = argv[argIndex++];
	toTempType = getTemperatureType(toTempTypeStr);

	if (toTempType == INVALID_TEMPERATURE_TYPE) {
		b9ac2bf7_invalidTemperatureType(programName, toTempTypeStr);
		b9ac2bf7_usageMessage(programName, NULL, fromTempType);
		exit(EXIT_FAILURE);
	}

	if (argc < 3) {
		b9ac2bf7_missingParameter(programName, "TEMPERATURE");
		b9ac2bf7_usageMessage(programName, toTempTypeStr, fromTempType);
		exit(EXIT_FAILURE);
	}

	temperatureStr = argv[argIndex++];
	convertedTemp = b9ac2bf7_convertTemperature(temperatureStr, fromTempType, toTempType);

	if (convertedTemp == FLT_MIN) {
		b9ac2bf7_invalidTemperature(programName, temperatureStr);
		b9ac2bf7_usageMessage(programName, toTempTypeStr, fromTempType);
		exit(EXIT_FAILURE);
	}

	printf("%s°%c -> %.2f°%c\n", temperatureStr, fromTempType, convertedTemp, toTempType);

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

TemperatureType getTemperatureType(char *argument) {

	if (f6215943_isEqual("celsius", argument)) {
		return CELSIUS;
	}

	if (f6215943_isEqual("fahrenheit", argument)) {
		return FAHRENHEIT;
	}

	if (f6215943_isEqual("kelvin", argument)) {
		return KELVIN;
	}

	return INVALID_TEMPERATURE_TYPE;
}
