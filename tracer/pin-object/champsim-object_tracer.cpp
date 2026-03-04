/*
 *    Copyright 2023 The ChampSim Contributors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*! @file
 *  This is an example of the PIN tool that demonstrates some basic PIN APIs
 *  and could serve as the starting point for developing your first PIN tool
 */

#include <fstream>
#include <iostream>
#include <stdlib.h>
#include <string.h>
#include <string>
#include <vector>
#include <algorithm>

#include "../../inc/trace_memobject.h"
#include "../../inc/trace_instruction.h"
#include "pin.H"

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#define FREE "_free"
#else
#define MALLOC "malloc"
#define FREE "free"
#endif

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_memobj_format_t = input_memobj;
using trace_instr_format_t = input_instr;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 instrCount = 0;
UINT64 memobjCount = 0;

std::ofstream outfile;       // pin instruction trace
std::ofstream memobjfile; // memory object trace

trace_instr_format_t curr_instr;
trace_memobj_format_t curr_memobj;

// forward declare free handler so Routine can reference it before its definition
VOID FreeObjectBefore(UINT64 ptr);

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "champsim_instruction.trace", "specify file name for Champsim-Object tracer output");
KNOB<std::string> KnobObjectFile(KNOB_MODE_WRITEONCE, "pintool", "m", "champsim_memobject.trace", "specify file name for Champsim-Object memory object tracer output");

KNOB<UINT64> KnobSkipInstructions(KNOB_MODE_WRITEONCE, "pintool", "s", "0", "How many instructions to skip before tracing begins");
KNOB<UINT64> KnobTraceInstructions(KNOB_MODE_WRITEONCE, "pintool", "t", "1000000", "How many instructions to trace");

/* ===================================================================== */
// Utilities
/* ===================================================================== */

/*!
 *  Print out help message.
 */
INT32 Usage()
{
  std::cerr << "This tool create a register and memory access trace" << std::endl
            << "  and a instruction trace" << std::endl
            << "  and a memory object trace" << std::endl
            << "Specify the output trace file with -o" << std::endl
            << "Specify the memory object trace file with -m" << std::endl
            << "Specify the number of instructions to skip before tracing with -s" << std::endl
            << "Specify the number of instructions to trace with -t" << std::endl
            << std::endl;

  std::cerr << KNOB_BASE::StringKnobSummary() << std::endl;

  return -1;
}

/* ===================================================================== */
// Analysis routines
/* ===================================================================== */

void ResetCurrentInstruction(VOID* ip)
{
  curr_instr           = {};
  curr_instr.ip        = (unsigned long long int)ip;
  curr_instr.timestamp = (unsigned long long int)instrCount;
}

BOOL ShouldWrite()
{
  ++instrCount;
  return (instrCount > KnobSkipInstructions.Value()) && (instrCount <= (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()));
}

void WriteCurrentInstruction()
{
  typename decltype(outfile)::char_type buf[sizeof(trace_instr_format_t)];
  std::memcpy(buf, &curr_instr, sizeof(trace_instr_format_t));
  outfile.write(buf, sizeof(trace_instr_format_t));
}

void BranchOrNot(UINT32 taken)
{
  curr_instr.is_branch = 1;
  curr_instr.branch_taken = taken;
}

template <typename T>
void WriteToSet(T* begin, T* end, UINT32 r)
{
  auto set_end = std::find(begin, end, 0);
  auto found_reg = std::find(begin, set_end, r); // check to see if this register is already in the list
  *found_reg = r;
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

// Is called for every instruction and instruments reads and writes
VOID Instruction(INS ins, VOID* v)
{
  // begin each instruction with this function
  INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)ResetCurrentInstruction, IARG_INST_PTR, IARG_END);

  // instrument branch instructions
  if (INS_IsBranch(ins))
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)BranchOrNot, IARG_BRANCH_TAKEN, IARG_END);

  // instrument register reads
  UINT32 readRegCount = INS_MaxNumRRegs(ins);
  for (UINT32 i = 0; i < readRegCount; i++) {
    UINT32 regNum = INS_RegR(ins, i);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>, IARG_PTR, curr_instr.source_registers, IARG_PTR,
                   curr_instr.source_registers + NUM_INSTR_SOURCES, IARG_UINT32, regNum, IARG_END);
  }

  // instrument register writes
  UINT32 writeRegCount = INS_MaxNumWRegs(ins);
  for (UINT32 i = 0; i < writeRegCount; i++) {
    UINT32 regNum = INS_RegW(ins, i);
    INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned char>, IARG_PTR, curr_instr.destination_registers, IARG_PTR,
                   curr_instr.destination_registers + NUM_INSTR_DESTINATIONS, IARG_UINT32, regNum, IARG_END);
  }

  // instrument memory reads and writes
  UINT32 memOperands = INS_MemoryOperandCount(ins);

  // Iterate over each memory operand of the instruction.
  for (UINT32 memOp = 0; memOp < memOperands; memOp++) {
    if (INS_MemoryOperandIsRead(ins, memOp))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>, IARG_PTR, curr_instr.source_memory, IARG_PTR,
                     curr_instr.source_memory + NUM_INSTR_SOURCES, IARG_MEMORYOP_EA, memOp, IARG_END);
    if (INS_MemoryOperandIsWritten(ins, memOp))
      INS_InsertCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteToSet<unsigned long long int>, IARG_PTR, curr_instr.destination_memory, IARG_PTR,
                     curr_instr.destination_memory + NUM_INSTR_DESTINATIONS, IARG_MEMORYOP_EA, memOp, IARG_END);
  }

  // finalize each instruction with this function
  INS_InsertIfCall(ins, IPOINT_BEFORE, (AFUNPTR)ShouldWrite, IARG_END);
  INS_InsertThenCall(ins, IPOINT_BEFORE, (AFUNPTR)WriteCurrentInstruction, IARG_END);
}

/* ===================================================================== */
// Instrumentation callbacks
/* ===================================================================== */

VOID AllocObjectBefore(UINT64 size)
{
  curr_memobj       = {};
  curr_memobj.osize = (unsigned long long)size;
}

VOID AllocObjectAfter(UINT64 ret)
{
  curr_memobj.obase     = (unsigned long long)ret;
  curr_memobj.timestamp = (unsigned long long)instrCount;

  if (instrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()))
    return;

  // write allocation record immediately
  curr_memobj.oid = (unsigned long long) memobjCount++;

  typename decltype(memobjfile)::char_type buf_obj[sizeof(trace_memobj_format_t)];
  std::memcpy(buf_obj, &curr_memobj, sizeof(trace_memobj_format_t));
  memobjfile.write(buf_obj, sizeof(trace_memobj_format_t));
}

/*!
 * Pin calls this function every time a new rtn is executed
 * If the rountine is mmap(), we insert a call at its entry point to increment the count
 * @param[in]   rtn      routine to be instrumented
 * @param[in]   v        value specified by the tool in the TRACE_AddInstrumentFunction
 *                       function call
 */
VOID Routine(RTN rtn, VOID*v)
{
  string mallocname(MALLOC);
  string freename(FREE);

  if ( RTN_Name(rtn).compare(mallocname) == 0 )
  {
    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)AllocObjectBefore, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);

    RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)AllocObjectAfter,
                IARG_FUNCRET_EXITPOINT_VALUE,
                IARG_END);

    RTN_Close(rtn);
  }

  if ( RTN_Name(rtn).compare(freename) == 0 )
  {
    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeObjectBefore, IARG_FUNCARG_ENTRYPOINT_VALUE, 0, IARG_END);

    RTN_Close(rtn);
  }
}

/*!
 * Print out analysis results.
 * This function is called when the application exits.
 * @param[in]   code            exit code of the application
 * @param[in]   v               value specified by the tool in the
 *                              PIN_AddFiniFunction function call
 */
VOID Fini(INT32 code, VOID* v) 
{ 
  // real-time writing is used; just close files
  memobjfile.close(); // close memory object trace file
  outfile.close();       // close instruction trace file
}

// Called before free(ptr) is executed
VOID FreeObjectBefore(UINT64 ptr)
{
  // only consider frees within tracing window
  if (instrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()))
    return;

  // create a new record for the freed object
  trace_memobj_format_t free_rec = {};
  free_rec.oid = 0; // 0 indicates this is a free record, not an allocation record
  free_rec.obase = (unsigned long long)ptr;
  free_rec.osize = 0; // size is already in the allocation record
  free_rec.timestamp = (unsigned long long)instrCount;
  free_rec.is_freed = 1; // mark as freed
  free_rec.otype = 0; // not applicable for free records

  // append the free record to the file
  memobjfile.seekp(0, std::ios::end);
  typename decltype(memobjfile)::char_type buf_free[sizeof(trace_memobj_format_t)];
  std::memcpy(buf_free, &free_rec, sizeof(trace_memobj_format_t));
  memobjfile.write(buf_free, sizeof(trace_memobj_format_t));
}

/*!
 * The main procedure of the tool.
 * This function is called when the application image is loaded but not yet started.
 * @param[in]   argc            total number of elements in the argv array
 * @param[in]   argv            array of command line arguments,
 *                              including pin -t <toolname> -- ...
 */
int main(int argc, char* argv[])
{
  PIN_InitSymbols();

  // Initialize PIN library. Print help message if -h(elp) is specified
  // in the command line or the command line is invalid
  if (PIN_Init(argc, argv))
    return Usage();

  outfile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cout << "Couldn't open instruction trace file. Exiting." << std::endl;
    exit(1);
  }

  memobjfile.open(KnobObjectFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!memobjfile) {
    std::cout << "Couldn't open memory object trace file. Exiting." << std::endl;
    exit(1);
  }

  // Register function to be called to instrument instructions
  INS_AddInstrumentFunction(Instruction, 0);

  // Register Routine to be called to instrument rtn
  RTN_AddInstrumentFunction(Routine, 0);

  // Register function to be called when the application exits
  PIN_AddFiniFunction(Fini, 0);

  // Start the program, never returns
  PIN_StartProgram();

  return 0;
}
