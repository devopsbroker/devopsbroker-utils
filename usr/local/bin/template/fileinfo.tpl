#!/bin/bash

#
# fileinfo.tpl - DevOpsBroker template script for generating HTML5 file information files
#
# Copyright (C) 2018 Edward Smith <edwardsmith@devopsbroker.org>
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
# Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-33
#
# -----------------------------------------------------------------------------
#

# ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Preprocessing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

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
fileName="$1"
fileSize="$2"
sha256Sum="$3"

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ OPTION Parsing ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Display usage if no file name parameter specified
if [ -z "$fileName" ]; then
	printUsage "fileinfo.tpl FILE_NAME FILE_SIZE SHA256SUM"
	exit 1
fi

# Display usage if no file size parameter specified
if [ -z "$fileSize" ]; then
	printUsage "fileinfo.tpl "$fileName" FILE_SIZE SHA256SUM"
	exit 1
fi

# Display usage if no SHA256SUM parameter specified
if [ -z "$sha256Sum" ]; then
	printUsage "fileinfo.tpl "$fileName" $fileSize SHA256SUM"
	exit 1
fi

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

fileSizeKB=$(echo "scale=2; $fileSize / 1024" | $EXEC_BC)

## Template
/bin/cat << EOF
<!DOCTYPE html>

<html>
<head>
  <meta charset="UTF-8">
  <meta name="description" content="File information ─ $fileName">

  <!-- Set the viewport for Responsive Web Design -->
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>File information ─ $fileName</title>
  <style>
    body {
      font: normal 11pt Verdana, Arial, sans-serif;
    }

    td {
      padding: 0.5em;
    }
  </style>
</head>
<body>
  <h3>File information for <kbd>$fileName</kbd>:</h3>
  <table>
    <tbody>
      <tr>
        <td><b>File Size</b></td>
        <td>$(printf "%'d" $fileSize) bytes ($(printf "%'2g" $fileSizeKB) KiB)</td>
      </tr>
      <tr>
        <td><b>SHA256 Checksum</b></td>
        <td><samp>$sha256Sum</samp></td>
      </tr>
    </tbody>
  </table>
</body>
</html>
EOF

exit 0
