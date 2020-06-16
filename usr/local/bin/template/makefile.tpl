#!/usr/bin/bash

#
# makefile.tpl - DevOpsBroker template script for generating makefiles
#
# Copyright (C) 2018-2020 Edward Smith <edwardsmith@devopsbroker.org>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------------
# Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-45
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Load /etc/devops/ansi.conf if ANSI_CONFIG is unset
if [ -z "$ANSI_CONFIG" ] && [ -f /etc/devops/ansi.conf ]; then
	source /etc/devops/ansi.conf
fi

${ANSI_CONFIG?"[1;91mCannot load '/etc/devops/ansi.conf': No such file[0m"}

# Load /etc/devops/exec.conf if EXEC_CONFIG is unset
if [ -z "$EXEC_CONFIG" ] && [ -f /etc/devops/exec.conf ]; then
	source /etc/devops/exec.conf
fi

${EXEC_CONFIG?"[1;91mCannot load '/etc/devops/exec.conf': No such file[0m"}

# Load /etc/devops/functions.conf if FUNC_CONFIG is unset
if [ -z "$FUNC_CONFIG" ] && [ -f /etc/devops/functions.conf ]; then
	source /etc/devops/functions.conf
fi

${FUNC_CONFIG?"[1;91mCannot load '/etc/devops/functions.conf': No such file[0m"}

################################## Variables ##################################

## Options
projectName="$1"

## Variables
YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no project name parameter specified
if [ -z "$projectName" ]; then
	printUsage "makefile.tpl PROJ_NAME"
	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/usr/bin/cat << EOF
#
# makefile - Description goes here
#
# Copyright (C) $YEAR AUTHOR_NAME <email@address.com>
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU General Public License as published by the Free Software
# Foundation, either version 3 of the License, or (at your option) any later
# version.
#
# This program is distributed in the hope that it will be useful, but WITHOUT
# ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
# FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more
# details.
#
# You should have received a copy of the GNU General Public License along with
# this program.  If not, see <http://www.gnu.org/licenses/>.
#
# -----------------------------------------------------------------------------
# Developed on $(getUbuntuRelease) running kernel.osrelease = $(getKernelVersion)
#
# -----------------------------------------------------------------------------
#

################################## Variables ##################################

TMPDIR ?= /tmp
SHELL := /bin/bash

CC := /usr/bin/gcc
CFLAGS := -Wall -g

################################### Targets ###################################

.PHONY: default clean printenv

default: $projectName

bin/$projectName.o: src/$projectName.c
	\$(CC) \$(CFLAGS) -c src/$projectName.c -o bin/$projectName.o

$projectName: bin/$projectName.o
	\$(CC) bin/$projectName.o -o $projectName

clean:
	/usr/bin/rm -f $projectName bin/$projectName.o

printenv:
	@echo "MAKEFILE_LIST: \$(MAKEFILE_LIST)"
	@echo "       TMPDIR: \$(TMPDIR)"
	@echo "       CURDIR: \$(CURDIR)"
	@echo

EOF
