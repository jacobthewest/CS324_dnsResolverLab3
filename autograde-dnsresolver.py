#!/usr/bin/env python3

"""
To see usage, run ./autograde-dnsresolver -h

Installation:
You must install dnspython first, you can do so via:
python -m pip install dnspython
(Must be Python 3)

Synopsis:

This grader works by setting up a small UDP proxy server that the submission will send a DNS query to. The grader records the query, then
responds with a canonical DNS answer for that query. It responds correctly even if the query that the submission sends is incorrect,
making it easier to identify bugs.

Each query is attempted twice, once with and without valgrind. After all queries are attempted, the grader parses the queries sent
by the submission and compares them to a reference DNS solution. 

If any query is different than the expected query, the grader provides an XOR of the two to faciliate debugging:
The query sent differs from the expected query:
    Expected query: b'ddbf010000010000000000000000010001'
    Actual query:   b'1b9701000001000000000000000000010001'
    XOR:            b'-id-000000000000000000000000010101ff'

"""

import logging
import os
import binascii
import dns.resolver
import sys
import argparse
from collections import namedtuple
import random
import socket
from threading import Thread, Event
import subprocess
import re
import time

memory_leaks = 'Memory Leaks'
compiler_warnings = 'Compiler Warnings'
well_formed_query = 'Well-formed DNS query message'
send_and_receive = 'Sends the query and receives the response'
finds_answer = 'Finds the answer in the answer section'
handles_cname = 'Handles CNAME records properly'
handles_nxdomain = 'Handles names that don\'t resolve'
handles_root = 'Handles the root name'

check_order = [
    memory_leaks,
    compiler_warnings,
    well_formed_query,
    send_and_receive,
    finds_answer,
    handles_cname,
    handles_nxdomain,
    handles_root,
]

points = {
    memory_leaks: 2,
    compiler_warnings: 3,
    well_formed_query: 25,
    send_and_receive: 20,
    finds_answer: 25,
    handles_cname: 10,
    handles_nxdomain: 10,
    handles_root: 5,
}


# We shouldn't have any query that is larger than this.
PROXY_MAX_READ_SIZE_BYTES = 8192

# Don't use any upper-case domain names unless the spec is changed to include that. The reference implementation forces lowercase, dnspython does not.
DEFAULT_DOMAINS = ['byu.edu', 'www.byu.edu', '.', 'casey.byu.edu', 'www.abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijk.com',
                   'sandia.gov', 'www.sandia.gov', 'foobarbaz-not-exist.byu.edu', 'www.intel.com']

SubmissionRunResult = namedtuple(
    'SubmissionRunResult', ['query_raw', 'stdout_raw', 'strace_output', 'valgrind_output', 'valgrind_exitcode', 'exitcode'])

TestResult = namedtuple('TestResult', [
                        'qname', 'output', 'expected_output', 'query_raw', 'expected_query_raw', 'strace_output', 'valgrind_output', 'valgrind_exitcode', 'exitcode'])


def parse_args():
    p = argparse.ArgumentParser(
        'DNS lab grader script that checks submissions by setting up a proxy dns server.')
    p.add_argument('-p', '--port', action='store', type=int,
            help='The port to run the dns proxy server on')
    p.add_argument('-t', '--timeout', action='store', type=int,
                   default=2, help='Timeout, in seconds, for each test.')
    p.add_argument('-s', '--dns-server', action='store', type=str,
                   default='8.8.8.8', help='DNS server to proxy to.')
    p.add_argument('-d', '--domains', nargs='+', action='store', default=DEFAULT_DOMAINS,
                   help='Domains to query. You must include a cname, a root name, a nxdomain, and a normal domain.')
    p.add_argument('-v', action='store_true', default=False,
                   help='Verbose. Show all point assignments.')
    return p.parse_args()


def main():
    args = parse_args()

    test_input = args.domains

    # Compile, check for warnings
    gcc_stderr = compile_resolver()

    # Run tests
    test_results = [x for x in run_tests(
        test_input, args.port, args.timeout, args.dns_server)]

    checks = {
        memory_leaks: passes_valgrind_check,
        compiler_warnings: None,  # special case since it applies for entire submission
        well_formed_query: passes_well_formed_query,
        send_and_receive: passes_send_and_receive,
        finds_answer: passes_finds_answers_not_cname,
        handles_cname: passes_finds_answers_cname,
        handles_nxdomain: passes_finds_answers_nxdomain,
        handles_root: passes_handles_root_name,
    }

    awarded_points_per_category = {}

    print('')

    for check_name in check_order:
        check = checks[check_name]

        max_points = points[check_name] * 1.0
        formatted_max_points = '{0:.2f}'.format(max_points)
        print('Checking and assigning points for "' + check_name +
              '" (max ' + formatted_max_points + ' points):')

        check_points = 0

        if check_name == compiler_warnings:
            if len(gcc_stderr) == 0:
                # no compiler warnings
                print('- PASS (' + formatted_max_points +
                      '/' + formatted_max_points + ')')
                check_points = max_points
            else:
                print('- FAIL (0/' + formatted_max_points +
                      '): There were compiler warnings.')

        else:
            check_results = [check(test_result)
                             for test_result in test_results]

            number_of_applied_tests = sum(
                [1 if r[0] else 0 for r in check_results])

            if number_of_applied_tests == 0:
                print('Unable to grade section ' +
                      check_name + ', no query names apply.')
                awarded_points_per_category[check_name] = 0
                continue

            points_per_test = max_points / number_of_applied_tests
            formatted_points_per_test = '{0:.2f}'.format(points_per_test)

            for check_result in check_results:

                # Skip tests that don't apply
                if check_result[0] == False:
                    continue

                points_to_award = points_per_test if check_result[1] else 0
                formatted_points_to_award = '{0:.2f}'.format(points_to_award)
                msg = [
                    '- PASS' if check_result[1] else '- FAIL',
                    '(' + formatted_points_to_award + '/' +
                    formatted_points_per_test + ' pts): '
                    '"' + check_result[3].qname + '"', ]
                print(' '.join(msg))

                if not check_result[1]:
                    print('    Failure reason: \n' + check_result[2])

                check_points += points_to_award

        print('Done checking for "' + check_name + '", awarding ' +
              '{0:.2f}'.format(check_points) + '/' + formatted_max_points + ' points\n')
        awarded_points_per_category[check_name] = check_points

    print('Done grading, awarded points:')
    for check_name in check_order:
        print('- ' + '{0:.2f}'.format(
            awarded_points_per_category[check_name]) + '/' + '{0:.2f}'.format(points[check_name]) + ' ' + check_name)

    final_score = sum(awarded_points_per_category.values())
    max_final_score = sum(points.values())
    print('\nFinal score: {0:.2f}/'.format(final_score) +
          '{0:.2f}'.format(max_final_score))

    return 0


def passes_valgrind_check(test_results):
    """
    All test cases can use valgrind, so we always return True, x, y.
    """

    if test_results.valgrind_exitcode == 0:
        return True, True, None, test_results
    else:
        return True, False, 'Valgrind exitcode was nonzero, indicating a memory error.', test_results


def passes_well_formed_query(test_results):

    raw_actual_query = test_results.query_raw[:]
    raw_expected_query = test_results.expected_query_raw[:]
    actual_query = binascii.hexlify(raw_actual_query)
    expected_query = binascii.hexlify(raw_expected_query)

    if actual_query[4:] == expected_query[4:]:
        return True, True, None, test_results

    # The actual and expected are different, find the differences.

    xor = b''
    for i in range(max(len(raw_actual_query), len(raw_expected_query))):
        # Ignore the first two bytes, which are the ID.
        if i < 2:
            if i == 0:
                xor += b'-id-'
            continue

        if i < len(raw_actual_query) and i < len(raw_expected_query):
            xor_next = raw_expected_query[i] ^ raw_actual_query[i]
        else:
            xor_next = 0xff
        xor += binascii.hexlify(bytes([xor_next]))

    ljust = 16
    reason = '\n'.join([
        'The query sent differs from the expected query:',
        'Expected query:'.ljust(ljust) + str(expected_query),
        'Actual query:'.ljust(ljust) + str(actual_query),
        'XOR:'.ljust(ljust) + str(xor)
    ])

    return True, False, reason, test_results


def passes_send_and_receive(test_results):

    if len(test_results.query_raw) == 0:
        return True, False, 'The submission did not send any data', test_results

    reads_from_socket = reads_from_socket_in_strace(test_results.strace_output)

    if reads_from_socket:
        return True, True, None, test_results
    else:
        return True, False, 'socket() and read() must be called at least once by your program', test_results


def passes_finds_answers_not_cname(test_results):

    # Don't run this check on any expected output that has a CNAME or is empty.
    has_any_cnames = any([not x.replace('.', '').isdigit()
                          for x in test_results.expected_output])
    if len(test_results.expected_output) == 0 or has_any_cnames:
        return False, None, None, test_results

    if test_results.exitcode != 0:
        reason = 'Exitcode was nonzero ({}), indicating submission likely crashed.'.format(
            test_results.exitcode)
        return True, False, reason, test_results

    return compare_dns_answers(test_results, 'The resolver did not find the correct answers from the response:')


def passes_finds_answers_cname(test_results):

    # Only run this check on nonempty responses with CNAMEs.
    has_any_cnames = any([not x.replace('.', '').isdigit()
                          for x in test_results.expected_output])
    if len(test_results.expected_output) == 0 or not has_any_cnames:
        return False, None, None, test_results

    if test_results.exitcode != 0:
        reason = 'Exitcode was nonzero ({}), indicating submission likely crashed.'.format(
            test_results.exitcode)
        return True, False, reason, test_results

    return compare_dns_answers(test_results, 'The resolver did not find the correct answers from the CNAME response:')


def passes_finds_answers_nxdomain(test_results):
    has_no_answer = len(
        test_results.expected_output) == 0 and test_results.qname != '.'

    if not has_no_answer:
        return False, None, None, test_results

    if test_results.exitcode != 0:
        reason = 'Exitcode was nonzero ({}), indicating submission likely crashed.'.format(
            test_results.exitcode)
        return True, False, reason, test_results

    return compare_dns_answers(test_results, 'The resolver did not correctly handle a name that didn\'t resolve:')


def passes_handles_root_name(test_results):
    is_root_name = test_results.qname == '.'

    if not is_root_name:
        return False, None, None, test_results

    if test_results.exitcode != 0:
        reason = 'Exitcode was nonzero ({}), indicating submission likely crashed.'.format(
            test_results.exitcode)
        return True, False, reason, test_results

    return compare_dns_answers(test_results, 'The resolver did not correctly handle the root name:')


def compare_dns_answers(test_results, failure_reason):
    expected = set(test_results.expected_output)
    actual = set(test_results.output)

    intersection = expected.intersection(actual)
    missing = expected.difference(actual)
    extra = actual.difference(expected)

    # no missing and no extra, pass test
    if len(missing) == 0 and len(extra) == 0:
        return True, True, None, test_results

    ljust = 16
    reason = '\n'.join([
        failure_reason,
        'Expected: '.ljust(ljust) + str(sorted(expected)),
        'Actual: '.ljust(ljust) + str(sorted(actual)),
        '(There are ' + str(len(extra)) + ' extra and ' +
        str(len(missing)) + ' missing answers)'
    ])

    return True, False, reason, test_results


def reads_from_socket_in_strace(stderr):
    """
    Returns true if a socket and read call are made by submission.
    """
    if stderr == None:
        return False

    stderr = stderr.decode('utf-8', errors='replace')
    socket_call = re.search('\nsocket\([^=]*= (\d)\n', stderr)

    if socket_call is None:
        return False

    socket_fd = socket_call.group(1)
    read_call = re.search('\nread\({},'.format(socket_fd), stderr)

    return read_call is not None


def run_tests(qnames, port, timeout, dns_server):

    for qname in qnames:
        print('Running submission for query name "{}"...'.format(qname))
        canonical_query = get_canonical_query(qname)
        canonical_response = get_canonical_response(
            canonical_query, dns_server)

        strace_result = run_submission_on_query(
            qname, canonical_response, port, timeout, use_valgrind=False)
        valgrind_result = run_submission_on_query(
            qname, canonical_response, port, timeout, use_valgrind=True)

        result = strace_result._replace(valgrind_output=valgrind_result.valgrind_output)._replace(
            valgrind_exitcode=valgrind_result.valgrind_exitcode)

        submission_results = parse_submission_output(result.stdout_raw)
        expected_results = get_expected_results(canonical_response)

        normalize_result(submission_results)
        normalize_result(expected_results)

        yield TestResult(qname=qname, output=submission_results, expected_output=expected_results, query_raw=result.query_raw, expected_query_raw=canonical_query.to_wire() or b'', strace_output=result.strace_output, valgrind_output=result.valgrind_output, valgrind_exitcode=result.valgrind_exitcode, exitcode=result.exitcode)


def normalize_result(result):
    """
    Make sure they all appear the same (ignore trailing . and case insensitivities).
    """
    for i in range(len(result)):
        result[i] = result[i].lower()
        if result[i][-1] == '.':
            continue
        if re.match('\d', result[i][-1]) != None:
            continue
        result[i] += '.'


def get_expected_results(response):
    results = []
    for cls in response.answer:
        for r in cls:
            results.append(str(r))

    return sorted(results)


def parse_submission_output(output):
    if not output:
        return []
    output = output.decode('utf-8', errors='replace')
    return [x for x in sorted(output.split('\n')) if x.strip() != '']


def get_canonical_query(qname):
    """
    Use dnspython to get query per spec.
    """
    # use qname.lower, as reference solution sends all qnames as lowercase.
    q = dns.message.make_query(qname.lower(), dns.rdatatype.A, use_edns=False)
    return q


def get_canonical_response(query_message, dns_server):
    """
    Send query to server and get response.
    """
    return dns.query.udp(query_message, dns_server)


def run_submission_on_query(qname, canonical_response, port, timeout, use_valgrind=False):
    """
    Start proxy server on known port.
    """

    result = {}
    settings = { 'ip': '127.0.0.1', 'port': port }
    ready = Event()
    response = canonical_response.to_wire()
    thread = Thread(target=proxy_server, args=(
        settings, response, result, timeout, ready))
    thread.start()

    ready.wait()

    port = settings['port']
    ip = settings['ip']
    if use_valgrind:
        args = ['valgrind', '--tool=memcheck', '--leak-check=full', '--error-exitcode=1',
                './resolver', qname, ip, str(port)]
    else:
        args = ['strace', './resolver', qname, ip, str(port)]

    run_result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    thread.join(timeout)

    if thread.is_alive():
        print('Error testing submission: timeout in test {} after {} seconds!'.format(
            qname, timeout))

    if use_valgrind:
        valgrind_exitcode = run_result.returncode
        valgrind_output = run_result.stderr or b''
        strace_output = None
    else:
        valgrind_exitcode = None
        valgrind_output = None
        strace_output = run_result.stderr or b''

    return SubmissionRunResult(query_raw=result.get('request', '') or b'', stdout_raw=run_result.stdout or b'', strace_output=strace_output, valgrind_output=valgrind_output, valgrind_exitcode=valgrind_exitcode, exitcode=run_result.returncode)


def proxy_server(settings, response, result, timeout, ready):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    port = settings['port']
    ip = settings['ip']
    #XXX
    port = None
    if port is None:
        i = 0
        while True:
            port = random.randint(1024, 65535)
            sa = (ip, port)
            try:
                sock.bind(sa)
            except PermissionError:
                i += 1
                if i == 5:
                    raise
            else:
                break
    else:
        sa = (ip, port)
        sock.bind(sa)
    settings['port'] = port
    ready.set()
    try:
        request, address = sock.recvfrom(PROXY_MAX_READ_SIZE_BYTES)
    except socket.timeout:
        print('test timed out!')
        return
    result['request'] = request
    sock.sendto(response, address)
    sock.close()


def compile_resolver():
    """
    We will take off points if there are compiler warnings.
    We will remove any old compiled program, recompile, and store stderr.
    """

    print('Removing old resolver executable (if it exists)')
    try:
        os.remove('resolver')
    except FileNotFoundError:
        pass

    args = ['gcc', '-g', 'resolver.c', '-o', 'resolver']

    print('Compiling resolver with command: "' + ' '.join(args) + '"')
    compile_result = subprocess.run(
        args, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    if compile_result.returncode != 0:
        raise CompilerError(
            'Unable to compile resolver.c. Run gcc manually to see the issue.')

    return compile_result.stderr


class CompilerError(Exception):
    pass


if __name__ == '__main__':
    exit(main())
