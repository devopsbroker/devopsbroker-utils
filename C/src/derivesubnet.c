/*
 * derivesubnet.c - DevOpsBroker utility for deriving IPv4 and IPv6 subnets
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
 * Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-38
 *
 * -----------------------------------------------------------------------------
 */

// ════════════════════════════ Feature Test Macros ═══════════════════════════

#define _DEFAULT_SOURCE

// ═════════════════════════════════ Includes ═════════════════════════════════

#include <stdbool.h>
#include <stdio.h>

#include <assert.h>
#include <unistd.h>

#include "org/devopsbroker/lang/error.h"
#include "org/devopsbroker/net/ipv4address.h"
#include "org/devopsbroker/net/ipv6address.h"
#include "org/devopsbroker/net/networkdevice.h"
#include "org/devopsbroker/socket/netlink.h"
#include "org/devopsbroker/socket/socket.h"
#include "org/devopsbroker/socket/unix.h"
#include "org/devopsbroker/terminal/commandline.h"

// ═══════════════════════════════ Preprocessor ═══════════════════════════════

#define USAGE_MSG "derivesubnet " ANSI_GOLD "{ -4 | -6 | -h }" ANSI_YELLOW " IF_NAME"

// ═════════════════════════════════ Typedefs ═════════════════════════════════

typedef struct DeviceParams {
	char *deviceName;
	bool  deriveIPv4Subnet;
	bool  deriveIPv6Subnet;
} DeviceParams;

static_assert(sizeof(DeviceParams) == 16, "Check your assumptions");

// ═════════════════════════════ Global Variables ═════════════════════════════


// ═══════════════════════════ Function Declarations ══════════════════════════

static void printHelp();

/* ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
 * Possible command-line options:
 *
 *   -4 -> Derive IPv4 Subnet
 *   -6 -> Derive IPv6 Subnet
 *   -h -> Help
 * ----------------------------------------------------------------------------
 */
static void processCmdLine(CmdLineParam *cmdLineParm, DeviceParams *deviceParams) {
	register int argc = cmdLineParm->argc;
	register char **argv = cmdLineParm->argv;

	// Perform initializations
	f668c4bd_meminit(deviceParams, sizeof(DeviceParams));
	deviceParams->deriveIPv4Subnet = true;

	for (int i = 1; i < argc; i++) {
		if (argv[i][0] == '-') {
			if (argv[i][1] == '4') {
				deviceParams->deriveIPv4Subnet = true;
				deviceParams->deriveIPv6Subnet = false;
			} else if (argv[i][1] == '6') {
				deviceParams->deriveIPv6Subnet = true;
				deviceParams->deriveIPv4Subnet = false;
			} else if (argv[i][1] == 'h') {
				printHelp();
				exit(EXIT_SUCCESS);
			} else {
				c7c88e52_invalidOption(argv[i]);
				c7c88e52_printUsage(USAGE_MSG);
				exit(EXIT_FAILURE);
			}
		} else {
			deviceParams->deviceName = argv[i];
		}
	}

	if (deviceParams->deviceName == NULL) {
		c7c88e52_missingParam("device name");
		c7c88e52_printUsage(USAGE_MSG);
		exit(EXIT_FAILURE);
	}
}

// ══════════════════════════════════ main() ══════════════════════════════════

int main(int argc, char *argv[]) {

	programName = "derivesubnet";

	DeviceParams deviceParams;
	CmdLineParam cmdLineParm;

	d7ad7024_initCmdLineParam(&cmdLineParm, argc, argv, USAGE_MSG);
	processCmdLine(&cmdLineParm, &deviceParams);

	UnixSocket unixSocket;
	NetworkDevice networkDevice;
	NetworkDeviceRequest ndRequest;

	f0185083_initNetworkDevice(&networkDevice, deviceParams.deviceName);
	f0185083_initNetworkDeviceRequest(&networkDevice, &ndRequest);

	bfdb2c2a_open(&unixSocket, UNIX_SOCK_DGRAM);
	f0185083_getNetworkDeviceIndex(&networkDevice, &ndRequest, &unixSocket);
	bfdb2c2a_close(&unixSocket);

	size_t bufSize = sysconf(_SC_PAGESIZE) - 72;
	NetlinkSocket *netlinkSocket = e7173ad4_createNetlinkSocket(NETLINK_ROUTE_ENUM, bufSize);

	// Initialize Netlink socket
	e7173ad4_open(netlinkSocket);
	a36b5966_setMaxSendBufferSize(netlinkSocket->fd, NETLINK_BUF_SIZE);
	a36b5966_setMaxRecvBufferSize(netlinkSocket->fd, NETLINK_BUF_SIZE);
	e7173ad4_setExtendedACKReporting(netlinkSocket, true);

	// Bind Netlink socket
	e7173ad4_bind(netlinkSocket);

	if (deviceParams.deriveIPv4Subnet) {
		f668c4bd_meminit(&networkDevice.ipv4Address, sizeof(IPv4Address));

		f0185083_getIPv4Address(&networkDevice, netlinkSocket);

		if (networkDevice.ipv4Address.address == 0) {
			c7c88e52_printNotice("Network device exists but cannot find IP address");

			// Close Netlink socket
			e7173ad4_close(netlinkSocket);
			e7173ad4_destroyNetlinkSocket(netlinkSocket);

			exit(EXIT_FAILURE);
		}

		f0185083_getIPv4Gateway(&networkDevice, netlinkSocket);
	} else {
		f668c4bd_meminit(&networkDevice.ipv6Global, sizeof(IPv6Address));
		f668c4bd_meminit(&networkDevice.ipv6Local, sizeof(IPv6Address));

		f0185083_getIPv6Addresses(&networkDevice, netlinkSocket);

		if (b7808f25_isIpAddressZero(&networkDevice.ipv6Global)) {
			c7c88e52_printNotice("Network device exists but cannot find IP address");

			// Close Netlink socket
			e7173ad4_close(netlinkSocket);
			e7173ad4_destroyNetlinkSocket(netlinkSocket);

			exit(EXIT_FAILURE);
		}

		f0185083_getIPv6Gateway(&networkDevice, netlinkSocket);
	}

	// Close Netlink socket
	e7173ad4_close(netlinkSocket);
	e7173ad4_destroyNetlinkSocket(netlinkSocket);

	if (deviceParams.deriveIPv4Subnet) {
		char ipAddrString[IPV4_STRBUF_LEN];

		e1e7e8f5_extractString(&networkDevice.ipv4Address, IPV4_ADDR | IVP4_CIDR_SUFFIX, ipAddrString);
		puts(ipAddrString);

		IPv4Address ipv4Gateway;
		ipv4Gateway.address = networkDevice.ipv4Gateway;
		e1e7e8f5_extractString(&ipv4Gateway, IPV4_ADDR, ipAddrString);
		puts(ipAddrString);

		e1e7e8f5_deriveSubnetMask(&networkDevice.ipv4Address);
		e1e7e8f5_extractString(&networkDevice.ipv4Address, IPV4_ROUTE, ipAddrString);
		puts(ipAddrString);
	} else {
		char ipAddrString[IPV6_STRBUF_LEN];

		b7808f25_extractString(&networkDevice.ipv6Global, ipAddrString);
		puts(ipAddrString);

		b7808f25_extractString(&networkDevice.ipv6Local, ipAddrString);
		puts(ipAddrString);

		b7808f25_extractString(&networkDevice.ipv6Gateway, ipAddrString);
		puts(ipAddrString);

		IPv6Address ipv6GlobalSubnet;
		b7808f25_deriveSubnet(&networkDevice.ipv6Global, &ipv6GlobalSubnet);
		b7808f25_extractString(&ipv6GlobalSubnet, ipAddrString);
		puts(ipAddrString);
	}

	// Exit with success
	exit(EXIT_SUCCESS);
}

// ═════════════════════════ Function Implementations ═════════════════════════

static void printHelp() {
	c7c88e52_printUsage(USAGE_MSG);

	puts("\nDerives the IPv4 routing prefix or IPv6 subnet for a network interface");

	puts(ANSI_BOLD "\nDefault Values:" ANSI_RESET);
	puts("  Protocol\tIPv4");

	puts(ANSI_BOLD "\nExamples:" ANSI_RESET);
	puts("  derivesubnet -6 enp31s0");

	puts(ANSI_BOLD "\nValid Options:\n");
	puts(ANSI_YELLOW "  -4\t" ANSI_ROMANTIC "Derive the IPv4 routing prefix");
	puts(ANSI_BOLD ANSI_YELLOW "  -6\t" ANSI_ROMANTIC "Derive the IPv6 subnet");
	puts(ANSI_BOLD ANSI_YELLOW "  -h\t" ANSI_ROMANTIC "Print this help message\n");
}
