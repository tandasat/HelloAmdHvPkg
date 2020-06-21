#! /usr/bin/env python3
#
# This script is invoked on VSCode on Ctrl + Shift + B to build the project with
# the EDK2 command and copy output to, say a USB drive.
# To run the script, Python3 is required. On Ubuntu, install it with
#   $ sudo apt-get install python-is-python3
import os
import subprocess
import platform
import shutil

# User configurations:
#   PACKAGE: the name of the package to compile
#   COPY_DEST: the directory to copy the compiled file specified as EFI_NAME
#   EFI_NAME: the build output to be copied to COPY_DEST
#   BUILD_TARGET: the build target, such as NOOPT and RELEASE
#   ARCHITECTURE: the build architecture such as x64
#   SERIAL_DEBUG: True to debug print on serial output. False for stdout.
#                 Beware of that if SERIAL_DEBUG is False, ASSERT is entirely
#                 ignored after the runtime unconditionally. This is a EDK2 thing.
PACKAGE = 'HelloAmdHvPkg'
COPY_DEST = 'D:\\'
EFI_NAME = 'HelloAmdHvDxe.efi'
BUILD_TARGET = 'NOOPT'
ARCHITECTURE = 'x64'
SERIAL_DEBUG = False

# Build variables based on the user configurations
edk_path = os.path.abspath('..')
if platform.system() == 'Linux':
    edk_setup = '. edksetup.sh'
    compiler = 'GCC5'
    executable = '/bin/bash'
elif platform.system() == 'Windows':
    edk_setup = 'edksetup.bat'
    compiler = 'VS2019'
    executable = None
else:
    raise NotImplementedError
if SERIAL_DEBUG:
    additional_parameters = '-D DEBUG_ON_SERIAL_PORT'
else:
    additional_parameters = ''

# Kick off the build command
os.chdir(edk_path)
cmd = f'{edk_setup} && build -t {compiler} -a X64 -b {BUILD_TARGET} -p {PACKAGE}/{PACKAGE}.dsc {additional_parameters}'
subprocess.call(cmd, shell=True, executable=executable)

# Copy the build output (.efi file) into the destination directory.
shutil.copy(
    os.path.join(edk_path, 'Build', PACKAGE, BUILD_TARGET + '_' + compiler, ARCHITECTURE, EFI_NAME),
    COPY_DEST,
)
