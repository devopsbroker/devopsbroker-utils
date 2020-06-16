#!/usr/bin/bash

#
# html5.tpl - DevOpsBroker template script for generating blank HTML5 files
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
# Developed on Ubuntu 16.04.5 LTS running kernel.osrelease = 4.15.0-33
#
# -----------------------------------------------------------------------------
#

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Template ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

## Template
/usr/bin/cat << EOF
<!DOCTYPE html>

<html>
<head>
  <meta charset="UTF-8">
  <meta name="description" content="New HTML Document">
  <meta name="author" content="AUTHOR_NAME">

  <!-- Set the viewport for Responsive Web Design -->
  <meta name="viewport" content="width=device-width, initial-scale=1.0">

  <title>New HTML Document</title>

  <style>
  </style>
</head>
<body>

  <!-- Content goes here -->
  <h1>New HTML Document</h1>

  <p>This is a blank template for a web page</p>

</body>
</html>
EOF

exit 0
