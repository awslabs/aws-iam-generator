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

lib_dir = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'bin', 'lib')
sys.path.append(lib_dir)
from config_helper import parse_cmdline


def run_sub_build(script, directory):
	args = parse_cmdline()
	cmd = [
		sys.executable,
		script,
		'-c',
		os.path.realpath(args.config),
		'-f',
		args.format,
		'-o',
		os.path.realpath(args.output_path),
		'-p',
		os.path.realpath(args.policy_path)
	]
	call = subprocess.Popen(
		cmd,
		cwd=os.path.dirname(os.path.realpath(__file__)) + "/" + directory,
		stdout=PIPE,
		stderr=PIPE
	)
	call.wait()
	if call.returncode == 0:
		return(call.stdout.read())
	else:
		print(call.stdout.read())
		print(call.stderr.read())
		raise RuntimeError("Sub build script failed")

if __name__ == '__main__':
	run_sub_build("iam_template_build.py", "bin")
