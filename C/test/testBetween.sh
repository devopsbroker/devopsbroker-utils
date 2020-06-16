#!/usr/bin/bash

#
# testBetween.sh - DevOpsBroker Bash test script for the between utility
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
# Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-43
#
# The latest unicode.html was downloaded using the following command:
#
# curl https://packages.ubuntu.com/bionic/all/unicode/filelist > unicode.html
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

## Script information
SCRIPT_DIR=$( $EXEC_DIRNAME "$BASH_SOURCE" )
EXEC_DIR="$SCRIPT_DIR/../bin"
DATA_DIR="$SCRIPT_DIR"/between

################################## Functions ##################################

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     negativeTest
# Description:  Expects a negative outcome from the applied test
#
# Parameter $1: START parameter
# Parameter $2: END parameter
# Parameter $3: Name of file to process
# -----------------------------------------------------------------------------
function negativeTest() {
	local exitCode=0

	# 1. Run the test
	$EXEC_BETWEEN $1 $2 $3 1>/dev/null 2>/dev/null
	exitCode=$?

	# 2. Check exit code for success/failure
	if [ $exitCode -ne 0 ]; then
		echo $pass
		return 0;
	else
		echo $fail
		return 1;
	fi
}

# ¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯¯
# Function:     positiveTest
# Description:  Expects a positive outcome from the applied test
#
# Parameter $1: START parameter
# Parameter $2: END parameter
# Parameter $3: Expected output file
# -----------------------------------------------------------------------------
function positiveTest() {
	local exitCode=0
	diffOutput=''

	# 1. Run the test and save output to $TMPDIR/$3.out
	if [ ! -z "$1" ] && [ ! -z "$2" ] && [ -z "$3" ]; then
		$EXEC_CAT "$DATA_DIR/pre-div-test.expect" | $EXEC_BETWEEN $1 $2
	else
		$EXEC_BETWEEN "$1" "$2" "$unicode" > "$TMPDIR/$3.out"
	fi
	exitCode=$?

	# 2. Check exit code for success/failure
	if [ $exitCode -ne 0 ]; then
		echo $fail
		return 1;
	elif [ -z "$3" ]; then
		echo $pass
		return 0;
	fi

	# 3. Compare expected and actual outputs
	diffOutput="$($EXEC_DIFF "$DATA_DIR/$3" "$TMPDIR/$3.out")"
	exitCode=$?

	if [ $exitCode -eq 0 ]; then
		# Clean up successful output file
		rm -f "$TMPDIR/$3.out"
		echo $pass
		return 0;
	else
		echo $fail
		return 1;
	fi
}

################################## Variables ##################################

## Bash exec variables
EXEC_BETWEEN="$EXEC_DIR/between"
EXEC_DIFF='/usr/bin/diff -ad'

## Variables
export TMPDIR=${TMPDIR:-'/tmp'}
diffOutput=''

# Data input file
unicode="$DATA_DIR/unicode.html"

# Pass/Fail messages
pass="${bold}${green}pass${reset}"
fail="${bold}${red}fail${reset}"

################################### Testing ###################################

# Clean any lingering .out files
$EXEC_RM -f "$TMPDIR/*.out"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Positive Testing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

printBanner 'Positive Testing'

# between "<pre>" "</pre>" unicode.html
echo -e 'between "<pre>" "</pre>" unicode.html\t\t'        "[$(positiveTest '<pre>' '</pre>' 'pre-test.expect')]"

if [ ! -z "$diffOutput" ]; then
	echo "$diffOutput"
fi

# between "<title>" "</title>" unicode.html
echo -e 'between "<title>" "</title>" unicode.html\t'      "[$(positiveTest '<title>' '</title>' 'title-test.expect')]"

if [ ! -z "$diffOutput" ]; then
	echo "$diffOutput"
fi

# between "</pre>" "</div>" unicode.html
echo -e 'between "</pre>" "</div>" unicode.html\t\t'       "[$(positiveTest '</pre>' '</div>' 'pre-div-test.expect')]"

if [ ! -z "$diffOutput" ]; then
	echo "$diffOutput"
fi

# between foo bar
echo -e 'between foo bar\t\t\t\t\t'                        "[$(positiveTest foo bar)]"

echo

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Negative Testing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

printBanner 'Negative Testing'

## Argument Testing
echo -e 'between\t\t\t\t\t\t'              "[$(negativeTest)]"
echo -e 'between foo\t\t\t\t\t'            "[$(negativeTest foo)]"
echo -e 'between foo bar baz\t\t\t\t'      "[$(negativeTest foo bar baz)]"

echo

exit 0
