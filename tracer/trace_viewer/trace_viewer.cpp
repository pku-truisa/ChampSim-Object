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
using input_instr_format_t = input_instr;

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
      printf("oid: %llu ; otimestamp: %llu; obase: 0x%llx ; osize: %llu \n", 
        curr_trace_memobj.oid,               // Memory ObjectID
        curr_trace_memobj.otimestamp,        // not free if zero
        curr_trace_memobj.obase,             // Memory Objecct Base Address
        curr_trace_memobj.osize              // Memory Object Size
        );
    }
  }

}

