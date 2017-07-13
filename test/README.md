# Joy Python Testing

## Introduction

This is a custom built python testing framework which is designed to assist in
validation of the Joy software as a whole. In contrast to unit testing, Joy is
treated as a black box and the information that the tests have at their disposal
is the input into Joy and the output that it produces. Despite the naming
similarity, this testing module has no relation or dependency on the popular
"pytest" python framework. The module has been developed with Python 2.7 in mind
so we recommend using that version.

## Running tests

The run_tests.py file is used to specify option/value combinations which
control the behavior of individual tests and specify which tests should be
run. To see which options are available, use the following command:

`./run_tests.py --help`

By default, the script will attempt to run all of the linked tests.
You can indicate a subset by exclusion:

`./run_tests.py --tls no`

The example above is telling the script to exclude both the TLS and IPFIX tests.
You may combine multiple excludes together.

Additionally, you can limit indicate a subset by inclusion:

`./run_tests.py --ipfix yes`

In that case, only the tests that are explicitly given a "yes" value will run.
You may combine multiple includes together.

#### Known Answer Tests

Many of the tests rely upon a set of known correct data that was recorded in the
past, in order to perform known answer tests (KAT) in present time. In this
module's terminology, we call the files that hold that KAT values the
"baseline"; you may have already noticed that keyword in some of the listed
options already.

Essentially, baseline files get generated at some point in time where we are
confident that the output of Joy is correct. This step of creating the baseline
files must be manually done by a human who has verified that the output looks
good. Now suppose that some changes are made to a particular module such as TLS.
Using the same input (pcap, etc.) that was used to generate the baseline files,
the modified module is run through the test and it's output is compared to the
stored baseline JSON data. If any differences exist then an error is thrown to
alert the user that there is a delta. The script will usually log which JSON
object in particular is different, but it is the responsibility of the user to
use deduce what is different between the new output and the baseline, and which
set of output is correct.
