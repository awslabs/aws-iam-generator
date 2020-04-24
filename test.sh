#!/bin/bash

set -ex

TESTDIR=test_output_templates

assert_templates_exist() {
    [ -f "${TESTDIR}/central(123456678910)-IAM.template" ]
    [ -f "${TESTDIR}/dev1(109876543210)-IAM.template" ]
    [ -f "${TESTDIR}/dev2(309876543210)-IAM.template" ]
    [ -f "${TESTDIR}/prod(209876543210)-IAM.template" ]
}

cleanup() {
    rm -f ${TESTDIR}/*
}

test_json() {
    cleanup
    ./build.py \
        --config sample_configs/config-complex.yaml \
        --format json \
        --output-path test_output_templates \
        --policy-path sample_policy
    assert_templates_exist
}

test_yaml() {
    cleanup
    ./build.py \
        --config sample_configs/config-complex.yaml \
        --format yaml \
        --output-path test_output_templates \
        --policy-path sample_policy_yaml
    assert_templates_exist
}

mkdir -p ${TESTDIR}
test_json
test_yaml
cleanup

echo 'All tests passed!'
