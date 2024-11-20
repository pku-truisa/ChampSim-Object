# Intel PIN tracer
# Object-Centric Architecture, contributed by Peking University

The included PIN tool `champsim-object_tracer.cpp` can be used to generate new traces.
It has been tested (April 2022) using PIN 3.22.

## Download and install PIN

Download the source of PIN from Intel's website, then build it in a location of your choice.

    wget https://software.intel.com/sites/landingpage/pintool/downloads/pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    tar zxf pin-3.22-98547-g7a303a835-gcc-linux.tar.gz
    cd pin-3.22-98547-g7a303a835-gcc-linux/source/tools
    make
    export PIN_ROOT=/your/path/to/pin

## Building the tracer

The provided makefile will generate `obj-intel64/champsim-object_tracer.so`.

    make
    $PIN_ROOT/pin -t obj-intel64/champsim-object_tracer.so -- <your program here>

The tracer has four options you can set:
```
-o
Specify the output file for your insrction trace.
The default is champsim_instruction.trace

-m
Specify the output file for your memory object trace.
the default is champsim_memobject.trace

-s <number>
Specify the number of instructions to skip in the program before tracing begins.
The default value is 0.

-t <number>
The number of instructions to trace, after -s instructions have been skipped.
The default value is 1,000,000.
```
For example, you could trace 200,000 instructions of the program ls, after skipping the first 100,000 instructions, with this command:

    pin -t obj/champsim-object_tracer.so -o traces/ls_trace.champsim -s 100000 -t 200000 -- ls

Traces created with the champsim-object_tracer.so are approximately 70 bytes per instruction, but they generally compress down to less than a byte per instruction using xz compression.

