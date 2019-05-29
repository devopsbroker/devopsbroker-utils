#
# makefile - DevOpsBroker makefile for the devopsbroker-utils Linux utilities package
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
# Developed on Ubuntu 16.04.4 LTS running kernel.osrelease = 4.13.0-43
#
# -----------------------------------------------------------------------------
#

################################### Includes ##################################

include /etc/devops/globals.mk

################################## Variables ##################################

ASM := /usr/bin/nasm
CC := /usr/bin/gcc
LDFLAGS := -m64

ifeq ($(DEBUG), 1)
    ASMFLAGS := -felf64 -gdwarf
    CFLAGS := -Wall -gdwarf -m64 -Og -fdiagnostics-color=always -DDEBUG
else
    ASMFLAGS := -felf64
    CFLAGS := -Wall -m64 -O2 -fdiagnostics-color=always -DNDEBUG
endif

BIN_DIR := bin
SRC_DIR := src
OBJ_DIR := obj
LIB_DIR := lib
LIBDEVOPSBROKER_DIR := $(realpath $(CURDIR)/../../libdevopsbroker)

C_SOURCES := $(shell /bin/ls $(SRC_DIR)/*.c)
C_BINARIES := $(subst src/,bin/,$(C_SOURCES:.c=))

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Exports ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export ASM
export ASMFLAGS
export CC
export CFLAGS

################################### Targets ###################################

.ONESHELL:
.PHONY: default clean prepare install ls printenv

default: prepare $(C_BINARIES)

clean:
	$(call printInfo,Cleaning $(OBJ_DIR) directory)
	/bin/rm -fv $(OBJ_DIR)/*
	$(call printInfo,Cleaning $(BIN_DIR) directory)
	/bin/rm -rfv $(BIN_DIR)/*
	$(call printInfo,Cleaning $(LIB_DIR) directory)
	/bin/rm -fv $(LIB_DIR)/*.a
	echo

prepare:
	/bin/mkdir -p --mode=750 $(OBJ_DIR)
	/bin/cp -ua $(LIBDEVOPSBROKER_DIR)/C/lib/libdevopsbroker.a $(LIB_DIR)/

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Object Files ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# Obtain object files for the C utilities
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c
	$(call printInfo,Compiling $(@F))
	$(CC) $(CFLAGS) -c $< -o $@

# Obtain object files for the ASM libraries
$(OBJ_DIR)/%.o: $(SRC_DIR)/%.asm
	$(call printInfo,Compiling $(@F))
	$(ASM) $(ASMFLAGS) $< -o $@

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Utilities ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

bin/between: obj/between.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@
	$(call printInfo,Testing $(@) executable)
	test/testBetween.sh

bin/convert-temp: obj/convert-temp.o obj/convert-temp.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@
	/usr/bin/strip -s $@

bin/derivesubnet: obj/derivesubnet.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/firechain: obj/firechain.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/firelog: obj/firelog.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/nettuner: obj/nettuner.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/schedtuner: obj/schedtuner.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/scriptinfo: obj/scriptinfo.o obj/scriptinfo.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@
	/usr/bin/strip -s $@

bin/trim: obj/trim.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/verifyclass: obj/verifyclass.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@

bin/verifyip: obj/verifyip.o obj/verifyip.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_DIR)/libdevopsbroker.a -o $@
	/usr/bin/strip -s $@
	$(call printInfo,Testing $(@) executable)
	test/testVerifyIP.sh

install: default
	/bin/cp -uv bin/between ../usr/local/bin
	/bin/cp -uv bin/convert-temp ../usr/local/bin
	/bin/cp -uv bin/derivesubnet ../usr/local/bin
	/bin/cp -uv bin/firechain ../usr/local/sbin
	/bin/cp -uv bin/firelog ../usr/local/bin
	/bin/cp -uv bin/nettuner ../usr/local/bin
	/bin/cp -uv bin/schedtuner ../usr/local/sbin
	/bin/cp -uv bin/scriptinfo ../usr/local/bin
	/bin/cp -uv bin/trim ../usr/local/bin
	/bin/cp -uv bin/verifyclass ../usr/local/bin
	/bin/cp -uv bin/verifyip ../usr/local/bin

ls:
	echo "Phony Targets:"
	echo "  default"
	echo "  clean"
	echo "  prepare"
	echo "  install"
	echo "  ls"
	echo "  printenv"
	echo
	echo "Executable Targets:"
	echo "  bin/between"
	echo "  bin/convert-temp"
	echo "  bin/derivesubnet"
	echo "  bin/firechain"
	echo "  bin/firelog"
	echo "  bin/nettuner"
	echo "  bin/schedtuner"
	echo "  bin/scriptinfo"
	echo "  bin/trim"
	echo "  bin/verifyclass"
	echo "  bin/verifyip"
	echo

printenv:
	echo "        MAKEFILE_LIST: $(MAKEFILE_LIST)"
	echo "         MAKECMDGOALS: $(MAKECMDGOALS)"
	echo "                DEBUG: $(DEBUG)"
	echo "               TMPDIR: $(TMPDIR)"
	echo "               CURDIR: $(CURDIR)"
	echo "              BIN_DIR: $(BIN_DIR)"
	echo "              SRC_DIR: $(SRC_DIR)"
	echo "              OBJ_DIR: $(OBJ_DIR)"
	echo "              LIB_DIR: $(LIB_DIR)"
	echo "  LIBDEVOPSBROKER_DIR: $(LIBDEVOPSBROKER_DIR)"
	echo "                  ASM: $(ASM)"
	echo "             ASMFLAGS: $(ASMFLAGS)"
	echo "                   CC: $(CC)"
	echo "               CFLAGS: $(CFLAGS)"
	echo "              LDFLAGS: $(LDFLAGS)"
	echo "           C_BINARIES: $(C_BINARIES)"
	echo
