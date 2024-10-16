#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "../pin-object/trace_memobject.h"
#include "../../inc/trace_instruction.h"

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_memobject_format_t = trace_memobject;
using trace_memfree_format_t = trace_memfree;

char tracefilename[1000];

bool view_memobject_trace = false;
bool view_memfree_trace = false;

int main(int argc, char** argv)
{
  printf("You have entered %d arguments:\n", argc);
  for (int i = 0; i < argc; i++) {
    printf("%s\n", argv[i]);
  }

  for (int i = 1; i < argc; i++) {
    if (!strcmp(argv[i], "-m"))
      view_memobject_trace = true;
    else if (!strcmp(argv[i], "-f"))
      view_memfree_trace = true;
    else
      strcpy(tracefilename, argv[i]);
  }

  // Open trace file for read
  printf("%s\n", tracefilename);
  auto tracefile = fopen(tracefilename, "r");
  if (!tracefile) {
    std::cout << "Couldn't open trace file. No Exiting." << std::endl;
    exit(1);
  }

  // Print trace file
  if (view_memobject_trace) {
    trace_memobject_format_t curr_trace_memobj;
    while(fread(&curr_trace_memobj, sizeof(trace_memobject_format_t), 1, tracefile)) {
      printf("oid: %llu osize: 0x%llx obase: 0x%llx start_instr: %llu end_instr: %llu \n", 
        curr_trace_memobj.oid,               // Memory ObjectID
        curr_trace_memobj.osize,             // Memory Object Size
        curr_trace_memobj.obase,             // Memory Objecct Base Address
        curr_trace_memobj.begin_instr_count, // invalid if zero
        curr_trace_memobj.end_instr_count    // not free if zero
        );
    }
  }

  if (view_memfree_trace) {
    trace_memfree_format_t curr_trace_memfree;
    while(fread(&curr_trace_memfree, sizeof(trace_memobject_format_t), 1, tracefile)) {
      printf("free_addr: %llx end_instr: %llu \n", 
        curr_trace_memfree.free_addr,
        curr_trace_memfree.end_instr_count    // not free if zero
        );
    }
  }
}

