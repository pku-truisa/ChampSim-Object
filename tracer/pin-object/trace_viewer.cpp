#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "trace_memobject.h"
#include "../../inc/trace_instruction.h"

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_memobject_format_t = trace_memobject;

char tracefilename[1000];

bool view_memobject_trace = false;

int main(int argc, char** argv)
{
  trace_memobject_format_t trace_memobject_buf;

  // defaults to reading from standard input

  strcpy(tracefilename, "-");

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-m"))
      view_memobject_trace = true;
    else
      strcpy(tracefilename, argv[i]);
  }

  // Open trace file for read
  auto tracefile = fopen(tracefilename, "r");
  if (!tracefile) {
    std::cout << "Couldn't open trace file. No Exiting." << std::endl;
    exit(1);
  }

  trace_memobject_format_t curr_trace_memobj;
  // Print trace file
  if (view_memobject_trace) {
    while(fread(&curr_trace_memobj, sizeof(trace_memobject_format_t), 1, tracefile)) {
      printf("oid: %llu osize: %llu obase: %llu start_instr: %llu end_instr: %llu", 
        curr_trace_memobj.oid,               // Memory ObjectID
        curr_trace_memobj.osize,             // Memory Object Size
        curr_trace_memobj.obase,             // Memory Objecct Base Address
        curr_trace_memobj.begin_instr_count, // invalid if zero
        curr_trace_memobj.end_instr_count    // not free if zero
        );
    }
  } 
}