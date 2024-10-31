#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>

#include "../../inc/trace_memobject.h"
#include "../../inc/trace_instruction.h"

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_memobject_format_t = input_memobject;
using trace_instr_format_t = input_instr;

char tracefilename[1000];

bool view_memobject_trace = false;
bool view_instruction_trace = false;

int main(int argc, char** argv)
{
  for (int i = 1; i < argc; i++) 
  {
    if ( strcmp(argv[i], "-m") == 0 )
      view_memobject_trace = true;
    else if ( strcmp(argv[i], "-i") == 0 )
      view_instruction_trace = true;
    else
      strcpy(tracefilename, argv[i]);
  }

  // Open trace file for read
  auto tracefile = fopen(tracefilename, "r");
  if ( !tracefile ) 
  {
    std::cout << "Couldn't open trace file. No Exiting." << std::endl;
    exit(1);
  }

  // View memory object trace file
  if ( view_memobject_trace ) 
  {
    trace_memobject_format_t curr_trace_memobj;

    while( fread(&curr_trace_memobj, sizeof(trace_memobject_format_t), 1, tracefile) ) 
    {
      //fprintf(stderr, "timestamp: %llu; oid: %llu ; obase: 0x%llx ; osize: %llu \n", 
      fprintf(stdout, "timestamp: %llu; oid: %llu ; obase: 0x%llx ; osize: %llu \n",
      curr_trace_memobj.timestamp,         // The Time after Malloc()
      curr_trace_memobj.oid,               // Memory ObjectID
      curr_trace_memobj.obase,             // Memory Objecct Base Address
      curr_trace_memobj.osize              // Memory Object Size
      );
    }
  }

  if ( view_instruction_trace) {
    trace_instr_format_t curr_trace_instr;
    while ( fread(&curr_trace_instr, sizeof(trace_instr_format_t), 1, tracefile) ) 
    {
      //fprintf(stderr, "timestamp: %llu; ip: %llx ; is_branch: %u ; branch_taken: %u \n", 
      fprintf(stdout, "timestamp: %llu; ip: %llx ; is_branch: %u ; branch_taken: %u \n",
      curr_trace_instr.timestamp,        // The Time after Malloc()
      curr_trace_instr.ip,               // Memory ObjectID
      curr_trace_instr.is_branch,        // Memory Objecct Base Address
      curr_trace_instr.branch_taken      // Memory Object Size
      );
    }
  }
}

