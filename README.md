Introduction
============

wtf is a "Wireless Test Framework". It's a collection of tests and support
systems for validating various WiFi devices and networks. In particular it is
designed to test the Laird WB WiFi devices.

Quick Start
===========

These instructions assume you have met the various prerequisites and
dependancies.

    cp platform/wb45/wtf-dcas.py ./wtfconfig.py
    # edit this file, in paricular adding your serial port and IP address info
    ./run

If you want to see the output as the tests run, you can run with the `-s`
flag:

    ./run -s

Troubleshooting
===============

Biggest initial problem and cause of failures is conflicting on the serial
port. If you have the serial port open in a terminal, WTF can't open it and
control your WB. When you run the test, the power-switch will thunk, and then
the test will almost immediately fail. Simple solution: close the serial port
and then run your tests. Don't try to be attached by the debug serial at the
same time. If you need the ins/outs during your work, use `./run -s`.

This failure looks like this:

        derosier@elmer:~/projects/wtf$ ./run
        E
        ======================================================================
        ERROR: test suite for <module 'dcas' from '/home/derosier/projects/wtf/tests/dcas.pyc'>
        ----------------------------------------------------------------------
        Traceback (most recent call last):
          File "/usr/lib/python2.7/dist-packages/nose/suite.py", line 208, in run
            self.setUp()
          File "/usr/lib/python2.7/dist-packages/nose/suite.py", line 291, in setUp
            self.setupContext(ancestor)
          File "/usr/lib/python2.7/dist-packages/nose/suite.py", line 314, in setupContext
            try_run(context, names)
          File "/usr/lib/python2.7/dist-packages/nose/util.py", line 469, in try_run
            return func(obj)
          File "/home/derosier/projects/wtf/tests/dcas.py", line 16, in setUp
            n.init_and_login()
          File "/home/derosier/projects/wtf/wtf/node/wb.py", line 70, in init_and_login
            self.init()
          File "/home/derosier/projects/wtf/wtf/node/wb.py", line 53, in init
            (r, output) = self.comm.wait_for('summit login:')
          File "/home/derosier/projects/wtf/wtf/comm/__init__.py", line 73, in wait_for
            (r, output) = self._wait_for(pattern)
          File "/home/derosier/projects/wtf/wtf/comm/__init__.py", line 127, in _wait_for
            r = self.ffd.expect_exact([pattern, pexpect.TIMEOUT])
          File "/usr/lib/python2.7/dist-packages/pexpect/__init__.py", line 1466, in expect_exact
            timeout, searchwindowsize)
          File "/usr/lib/python2.7/dist-packages/pexpect/__init__.py", line 1521, in expect_loop
            raise EOF(str(err) + '\n' + str(self))
        EOF: End Of File (EOF). Empty string style platform.
        <pexpect.fdpexpect.fdspawn object at 0x7fd4d1d0b990>
        version: 3.1
        command: None
        args: None
        searcher: <pexpect.searcher_string object at 0x7fd4d1a96410>
        buffer (last 100 chars): ''
        before (last 100 chars): ''
        after: <class 'pexpect.EOF'>
        match: None
        match_index: None
        exitstatus: None
        flag_eof: True
        pid: None
        child_fd: 4
        closed: False
        timeout: 60
        delimiter: <class 'pexpect.EOF'>
        logfile: None
        logfile_read: None
        logfile_send: None
        maxread: 2000
        ignorecase: False
        searchwindowsize: None
        delaybeforesend: 0.05
        delayafterclose: 0.1
        delayafterterminate: 0.1
        -------------------- >> begin captured stdout << ---------------------
        Turning OFF 6: 200
        Turning ON 6: 200
        WB45-2 wait-for: "summit login:"

        --------------------- >> end captured stdout << ----------------------

        ----------------------------------------------------------------------
        Ran 0 tests in 2.355s

        FAILED (errors=1)


Requirements
============

1. Python. This has been tested with python2.7
2. pyserial, nose, pexpect `sudo apt-get install python-nose python-pexpect`
3. For DCAS testing, you must have built dcal_py and it must be in your path.

Configuration
=============

In order to run the tests, you must first have a `wtfconfig.py` file in the
base directory of WTF. This file imports the components that are being used,
sets up the configuration of those components, hardware, nodes, etc. Finally,
you can select the test suites, tests, etc to run.

In `platform/*/` there are example `wtfconfig.py` files. Use these as a base,
copy them over and edit the configuration as necessary for your setup. Note
that `./wtfconfig.py` is listed in the `.gitignore` file. This is intended as
a personal setup, not for committing.  If you have a good example file for a
situation not already covered in the sample configs, feel free to copy it in,
give it an appropriate name and commit it.

Adding Tests
============

If all you want to do is add tests, open up the relevant file in the tests
subdirectory. You can tell which test suite you're working on by finding the
`suites = ["something"]` line in  your `wtfconfig.py` file.

The tests use the components in wtf, mainly the node and dcal modules. If you
need new functionality that isn't already existing, you'll have to add more
features to those modules.

DCAL/DCAS
=========

WTF uses a python binding to the dcal library called `dcal_py`. This is
produced as an optional component of the dcal library.

In order to do DCAL and DCAS testing, you must clone and fully build DCAL,
including the `dcal_py` component. For details on how to build this, please
see the README.md in the dcal.git repository.

In order for WTF to find the `dcal_py` module, you have to make sure that it
is located in the search path that python uses to find modules. Additionally,
it requires that the libdcal.so files can be found and loaded. The easiest way
to ensure this is to use `LD_LIBRARY_PATH` and `PYTHONPATH` environment
variables. Set these before you run.

    cd /path/to/dcal/clone
    export PYTHONPATH="$PWD"
    export LD_LIBRARY_PATH="$PWD:$LD_LIBRARY_PATH"

The proper configuration file to start with is
`platform/wb45/wtfconfig-dcas.py`. Copy this to your `wtfconfig.py` and then
edit the settings as necessary.

Adding more DCAL/DCAS tests
---------------------------

So, you're already using the above instructions and have set it up and have it
working, right? If not *go do that now*! This test framework worked at the
point I committed it, so get it working first, then muck with it.

Done, right?  OK, lets' move on...

So, for dcal/dcas testing you'll be working with the following areas:

### DCAL ###

Specifically the `dcal_py module`. You'll clone that project, and find what
you need in `src/python_binding.cpp`. Go look at the dcal project README for
instructions.

You'll need to add the wrapper bindings for each dcal function and build the
python target. Generally speaking, each api function will have an equivalent
binding - we are trying to validate DCAS and the DCAL API.

Why go to the "trouble" of wrapping the API so we can use it directly from
Python? Why not just build some C programs and run those? Simple - the session
can't be maintained across executions, nor can the API. So either we create C
programs for every single test we want to create (which could be hundreds!) or
we somehow create a single-call driver C program. That program would end up
being very complex. Neither option is very good, and besides, we don't want to
validate the C client program using the API, we want to validate the API. I
know it seems like more trouble than it's worth, but it's way faster this way.

So, create the bindings. It uses boost::python. Between the boost::python
documentation and the ones that have already been done, hopefully there is
enough pattern to follow.

A few notes:
* It is hard to return values via passed in arguments. For functions with
complicated return-argument sets, I've created classes to wrap those
components.
* Direct access of properties use `.def_readwrite()`, function calls use
`.def()`.
* Return strings as returns from getter functions as `boost::python::object`.
Trust me.
* For those complicated return-via-argument functions that I've created simple
classes for, you pass those in as references. eg `int version_pull( class version & v)`.
In particular see this function and the related version class as a good example.
* All API wrappers return int - same as the DCAL API. Just return the API
call's return.

### wtf/dcal ###

The code calling `dcal_py` is in the wtf.dcal module. Look at
`wtf/dcal/__init__` for the code. Again, generally-speaking we have calls for
every API you might want to call. In a few cases, we've combined items that
don't make sense except when working together; after all, we do want to
simplify our test cases if possible. A prime example is the session open()
call - obviously this is the place to include the host(), port() and other
calls.

You can see in the initialization, we create our single dcal instance. It's
saved as self.d. You call all class dcal functions via self.d.  eg.
`self.d.session_open()`.  In this example, `session_open()` is the actual call
in `dcal_py`.

For functions that take new objects, you have to create them first. Example
from `version()`:

    wb_version = dcal_py.version()
    ret = self.d.version_pull( wb_version)

### wb ###

Do you need the WB to do something? Perhaps for example, you want to do
something via DCAL, and then want to verify it by running a command on the WB.
That's fine, edit `wtf/node/wb.py` to add capabilities. One already in-place
feature is grepping the syslog for a string.

### tests ###

Time to add more tests? `tests/dcas.py` is the place.  Tests are run in
lexical order, hence the 00nn numbering, as test order may matter. Try to make
the tests independent if possible and not depend on order, nor on the last
state. At the moment the only one that must be run first is the first one, the
others are only ordered to be consistent. (`test_0001_session` must run first
because we want to be sure to catch the log messages from this run, and
clearing the log messages screws up dcas).

If you've done everything right, each test should be pretty simple, only a few
lines. All the heavy lifting should be done by the modules.  The basic pattern
will be:

    def test_mytest(self):
        for n in wtfconfig.nodes:
            n.dcal_open()
            # do some dcal calls and whatever else live testing you need
            n.dcal_close()
            # do other testing - most likely validate the data you got back

Note that the various calls will return exceptions that will get caught by
nose - you generally don't have to return values and check them from a call
(do that in the modules and use `raise`). use `self.failIf()` to validate data
coming back.


