#!/usr/bin/bash

#
# bash-complete.tpl - DevOpsBroker template for generating Bash complete scripts
#
# Copyright (C) 2018-2019 Edward Smith <edwardsmith@devopsbroker.org>
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
# Developed on Ubuntu 18.04.1 LTS running kernel.osrelease = 4.15.0-39
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

## Bash exec variables
EXEC_WHICH=/usr/bin/which

## Options
commandName="$1"

## Variables
YEAR=$($EXEC_DATE +'%Y')

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no parameters given
if [ -z "$commandName" ]; then
	printUsage 'bash-complete.tpl COMMAND'
	exit 1
fi

# Display error if command does not exist or is not executable
if ! $EXEC_WHICH $commandName 1>/dev/null; then
	printError 'bash-complete.tpl' "Command not found: '$commandName'"
	echo
	printUsage 'bash-complete.tpl COMMAND'

	exit 1
fi

# Display error if file already exists
if [ -f "$commandName" ] && [ -s "$commandName" ]; then
	printError 'bash-complete.tpl' "File already exists: '$commandName'"
	echo
	printUsage 'bash-complete.tpl COMMAND'

	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

functionName="_$commandName"

## Template
/usr/bin/cat << EOF
#!/usr/bin/bash

#
# $commandName - Bash completion script for the $commandName utility
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
# The following bash variables are provided in order to facilitate command
# completion:
#
#   o COMP_WORDS: Array of all words typed on the command-line
#   o COMP_CWORD: The COMP_WORDS index of the current word based on cursor placement
#   o COMP_LINE: The current command-line
#
# All possible matches for command completion go into the COMPREPLY array.
#
# Registering Bash completion scripts:
#   o Local: source <path-to-your-script>/$commandName
#   o Global: copy $commandName to the /etc/bash_completion.d directory
# -----------------------------------------------------------------------------
#

function ${functionName}() {

	COMPREPLY=()
	currentWord=\${COMP_WORDS[COMP_CWORD]}

}

complete -F $functionName $commandName

EOF

exit 0
