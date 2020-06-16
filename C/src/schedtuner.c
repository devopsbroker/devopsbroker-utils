/*
 * schedtuner.c - DevOpsBroker utility for tuning the Completely Fair Scheduler
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
 * Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-34
 *
 * As the Completely Fair Scheduler was released in October 2007, I am using
 * the following hardware spec as a frame of reference for calculating the CFS
 * values:
 *
 * Intel Core 2 Duo E4500
 *   o Number of Cores: 2
 *   o Clock Speed: 2.2 GHz
 *   o Memory Bus Speed: DDR2 800 MHz
 *
 * Memory Contention Coefficient (MCC):
 *   o (Number of Cores * Clock Speed) / Memory Bus Speed
 *   o BASE_MCC = (2 * 2200000000) / 800000000 = 5.5
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <assert.h>
#include <unistd.h>

#include "org/devopsbroker/info/cpuid.h"
#include "org/devopsbroker/io/file.h"
#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/lang/memory.h"
#include "org/devopsbroker/lang/units.h"
#include "org/devopsbroker/sysfs/memoryarray.h"
#include "org/devopsbroker/terminal/commandline.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define BASE_CPU_CLOCK_SPEED 2200.0
#define BASE_RAM_CLOCK_SPEED 800.0

#define MIN_GRANULARITY_FACTOR 0.65625
#define WAKEUP_GRANULARITY_FACTOR 0.40625

#define USAGE_MSG "schedtuner " ANSI_GOLD "{ -f cpuMaxFreq | -m memBusSpeed | -h }"

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef struct TuningParams {
	uint32_t cpuMaxFreq;
	uint32_t memoryBusSpeed;
} TuningParams;

static_assert(sizeof(TuningParams) == 8, "Check your assumptions");

// ═════════════════════════════ Global Variables ═════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

static uint32_t getCPUMaxFrequency(TuningParams *tuningParams);

static uint32_t getMemoryBusSpeed(TuningParams *tuningParams);

static void printHelp();

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Possible command-line options:
 *
 *   -f -> CPU Max Frequency
 *   -m -> Memory Bus Speed
 *   -h -> Help
 * ----------------------------------------------------------------------------
 */
static void processCmdLine(CmdLineParam *cmdLineParm, TuningParams *tuningParams) {
	register int argc = cmdLineParm->argc;
	register char **argv = cmdLineParm->argv;

	// Perform initializations
	f668c4bd_meminit(tuningParams, sizeof(TuningParams));

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == 'f') {
				tuningParams->cpuMaxFreq = d7ad7024_getUint64(cmdLineParm, "CPU maximum frequency", i++);
			} else if (argv[i][1] == 'm') {
				tuningParams->memoryBusSpeed = d7ad7024_getUint64(cmdLineParm, "memory bus speed", i++);
			} else if (argv[i][1] == 'h') {
				printHelp();
				exit(EXIT_SUCCESS);
			} else {
				c7c88e52_invalidOption(argv[i]);
				c7c88e52_printUsage(USAGE_MSG);
				exit(EXIT_FAILURE);
			}
		} else {
			c7c88e52_invalidOption(argv[i]);
			c7c88e52_printUsage(USAGE_MSG);
			exit(EXIT_FAILURE);
		}
	}
}

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "schedtuner";
	c7c88e52_ensureUserIsRoot();

	TuningParams tuningParams;
	CmdLineParam cmdLineParm;

	d7ad7024_initCmdLineParam(&cmdLineParm, argc, argv, USAGE_MSG);
	processCmdLine(&cmdLineParm, &tuningParams);

	CPUID cpuid;
	f618482d_getCoreTopology(&cpuid);

	// Calcualte the CFS attributes
	uint32_t schedLatencyNs = 6000000U;
	uint32_t schedMinGranularityNs;
	uint32_t schedWakeupGranularityNs;

	uint32_t cpuMaxFreq = getCPUMaxFrequency(&tuningParams);
	uint32_t memoryBusSpeed = getMemoryBusSpeed(&tuningParams);

	// Calculate the CPU and memory clock speed ratio
	double clockSpeedRatio = (cpuMaxFreq / BASE_CPU_CLOCK_SPEED) - 1;
	clockSpeedRatio += ((memoryBusSpeed / BASE_RAM_CLOCK_SPEED) - 1);

	// Adjust scheduled latency according to the clock speed ratio
	schedLatencyNs /= clockSpeedRatio;

	// Calculate minimum granularity and wakeup granularity
	schedMinGranularityNs = (schedLatencyNs * MIN_GRANULARITY_FACTOR);
	schedWakeupGranularityNs = (schedLatencyNs * WAKEUP_GRANULARITY_FACTOR);

	printf("kernel.sched_child_runs_first = 1\n");
	printf("kernel.sched_latency_ns = %u\n", schedLatencyNs);
	printf("kernel.sched_min_granularity_ns = %u\n", schedMinGranularityNs);
	printf("kernel.sched_schedstats = 0\n");
	printf("kernel.sched_tunable_scaling = 0\n");
	printf("kernel.sched_wakeup_granularity_ns = %u\n", schedWakeupGranularityNs);

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

static uint32_t getCPUMaxFrequency(TuningParams *tuningParams) {
	if (tuningParams->cpuMaxFreq == 0) {
		return e2f74138_read_uint64("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq") / UNITS_KHz;
	}

	return tuningParams->cpuMaxFreq;
}

static uint32_t getMemoryBusSpeed(TuningParams *tuningParams) {
	if (tuningParams->memoryBusSpeed == 0) {
		register MemoryArray *memoryInfo = f004d1bd_createMemoryArray();
		register uint32_t memoryBusSpeed = memoryInfo->minSpeed;

		if (memoryInfo->numChannelsInUse == 4) {
			memoryBusSpeed <<= 1;
		} else if (memoryInfo->numChannelsInUse == 3) {
			memoryBusSpeed += (memoryBusSpeed >> 1);
		} else if (memoryInfo->numChannelsInUse == 1) {
			memoryBusSpeed >>= 1;
		}

		f004d1bd_destroyMemoryArray(memoryInfo);

		return memoryBusSpeed;
	}

	return tuningParams->memoryBusSpeed;
}

static void printHelp() {
	c7c88e52_printUsage(USAGE_MSG);

	puts("\nPerforms kernel process scheduler optimization calculations for /etc/sysctl.conf");

	puts(ANSI_BOLD "\nDefault Values:" ANSI_RESET);
	puts("  CPU Max Frequency\tsysfs value (if present)");
	puts("  Memory Bus Speed\tdmidecode value (if present)");

	puts(ANSI_BOLD "\nExamples:" ANSI_RESET);
	puts("  schedtuner -f 3400 -m 3200");

	puts(ANSI_BOLD "\nValid Options:\n");
	puts(ANSI_YELLOW "  -f\t" ANSI_ROMANTIC "Specify the CPU maximum frequency");
	puts(ANSI_BOLD ANSI_YELLOW "  -m\t" ANSI_ROMANTIC "Specify the memory bus speed");
	puts(ANSI_BOLD ANSI_YELLOW "  -h\t" ANSI_ROMANTIC "Print this help message\n");
}
