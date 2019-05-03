#!/usr/bin/env python

# Copyright 2016 Amazon.com, Inc. or its affiliates.
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License").
# You may not use this file except in compliance with the License.
# A copy of the License is located at
#
#    http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file.
# This file is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
# CONDITIONS OF ANY KIND, either express or implied. See the License for the
# specific language governing permissions and limitations under the License.

import json
import os
import subprocess
from subprocess import PIPE
import sys

bin_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bin')
lib_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bin', 'lib')
sys.path.append(lib_dir)
sys.path.append(bin_dir)

from config_helper import parse_cmdline
from iam_template_build import main

if __name__ == '__main__':
	args = parse_cmdline()
	main(args)
