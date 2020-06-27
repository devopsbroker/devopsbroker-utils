#
# makefile - DevOpsBroker makefile for the devopsbroker-utils Linux utilities package
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

BIN_DIR := bin/
SRC_DIR := src/
OBJ_DIR := obj/
LIB_NAMES := -ldevopsbroker

C_SOURCES := $(shell /usr/bin/find $(SRC_DIR) -type f -name "*.c")
C_OBJECTS := $(subst src/,obj/,$(C_SOURCES:.c=.o))
C_BINARIES := $(subst obj/,bin/,$(C_OBJECTS:.o=))

ASM_SOURCES := $(shell /usr/bin/find $(SRC_DIR) -type f -name "*.asm")
ASM_OBJECTS := $(subst src/,obj/,$(ASM_SOURCES:.asm=.o))

EXEC_CP :=  $(shell which cp)
EXEC_MKDIR := $(shell which mkdir)
EXEC_RM := $(shell which rm)
EXEC_STRIP := $(shell which strip)

#~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~ Exports ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

export ASM
export ASMFLAGS
export CC
export CFLAGS

################################### Targets ###################################

.ONESHELL:
.SILENT:
.PHONY: default clean prepare install ls printenv

default: prepare $(C_BINARIES)

clean:
	$(call printInfo,Cleaning $(OBJ_DIR) directory)
	$(EXEC_RM) -rfv $(OBJ_DIR)
	$(call printInfo,Cleaning $(BIN_DIR) directory)
	$(EXEC_RM) -fv $(BIN_DIR)/*
	echo

prepare:
	$(EXEC_MKDIR) --parents --mode=750 $(OBJ_DIR)

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

bin/between: $(OBJ_DIR)/between.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(call printInfo,Testing $(@) executable)
	test/testBetween.sh

bin/convert-temp: $(OBJ_DIR)/convert-temp.o $(OBJ_DIR)/convert-temp.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/derivesubnet: $(OBJ_DIR)/derivesubnet.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/firechain: $(OBJ_DIR)/firechain.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/firelog: $(OBJ_DIR)/firelog.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/md5hash: $(OBJ_DIR)/md5hash.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@

bin/nettuner: $(OBJ_DIR)/nettuner.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/odfgrep: $(OBJ_DIR)/odfgrep.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@

bin/schedtuner: $(OBJ_DIR)/schedtuner.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/scriptinfo: $(OBJ_DIR)/scriptinfo.o $(OBJ_DIR)/scriptinfo.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/trim: $(OBJ_DIR)/trim.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/verifyclass: $(OBJ_DIR)/verifyclass.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@

bin/verifyip: $(OBJ_DIR)/verifyip.o $(OBJ_DIR)/verifyip.linux.o
	$(call printInfo,Creating $(@) executable)
	$(CC) $(LDFLAGS) $^ $(LIB_NAMES) -o $@
	$(EXEC_STRIP) -s $@
	$(call printInfo,Testing $(@) executable)
	test/testVerifyIP.sh

install: default
	$(EXEC_CP) -uv bin/between ../usr/local/bin
	$(EXEC_CP) -uv bin/convert-temp ../usr/local/bin
	$(EXEC_CP) -uv bin/derivesubnet ../usr/local/bin
	$(EXEC_CP) -uv bin/firechain ../usr/local/sbin
	$(EXEC_CP) -uv bin/firelog ../usr/local/bin
	$(EXEC_CP) -uv bin/md5hash ../usr/local/bin
	$(EXEC_CP) -uv bin/nettuner ../usr/local/bin
	$(EXEC_CP) -uv bin/odfgrep ../usr/local/bin
	$(EXEC_CP) -uv bin/schedtuner ../usr/local/sbin
	$(EXEC_CP) -uv bin/scriptinfo ../usr/local/bin
	$(EXEC_CP) -uv bin/trim ../usr/local/bin
	$(EXEC_CP) -uv bin/verifyclass ../usr/local/bin
	$(EXEC_CP) -uv bin/verifyip ../usr/local/bin

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
	echo "  bin/md5hash"
	echo "  bin/nettuner"
	echo "  bin/odfgrep"
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
