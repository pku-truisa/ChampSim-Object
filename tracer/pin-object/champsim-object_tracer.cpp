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

#include "trace_memobject.h"
#include "pin.H"

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_instr_format_t = trace_instr;
using trace_memobject_format_t = trace_memobject;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 instrCount = 0;
UINT64 memobjCount = 1;

std::ofstream outfile;       // instruction trace
std::ofstream memobjectfile; // memory object trace
std::ofstream tracefile;     // output trace

trace_instr_format_t curr_instr;

vector<trace_memobject_format_t> memobject_history;

bool inside_routine = false;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobOutputFile(KNOB_MODE_WRITEONCE, "pintool", "o", "champsim.trace", "specify file name for Champsim-Object tracer output");
KNOB<std::string> KnobInstrFile(KNOB_MODE_WRITEONCE, "pintool", "i", "champsim_instr.trace", "specify file name for Champsim instruction tracer output");
KNOB<std::string> KnobObjectFile(KNOB_MODE_WRITEONCE, "pintool", "m", "champsim_memobject.trace", "specify file name for Champsim memory object tracer output");

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
            << "  and a memory object allocation trace" << std::endl
            << "Specify the output instruction trace file with -o" << std::endl
            << "Specify the output memory object trace file with -m" << std::endl
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
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;
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


VOID AllocObjectBefore(UINT64 size)
{
  // Simulation Stop
  return (insCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()));
    
  trace_memobject_format_t curr_memobject = {};    

  curr_memobject.memobject_id = memobjCount;
  curr_memobject.memobject_size = (unsinged long long) size;
  curr_memobject.memobject_base = 0;
  curr_memobject.memobject_start_instr_count = insCount;
  curr_memobject.memobject_end_instr_count = 0;

  memobject_history.push_back(curr_memobject);

  inside_routine = true;
  ++memobjCount;
}

VOID AllocObjectAfter(UINT64 ret)
{
  // Simulation Stop
  return (insCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()));

  inside_routine= false;
  memobject_history.rbegin()->memobject_base = ret;

  trace_memobject_format_t buf_memobject = {};

  buf.memobject_id                = ranges.rbegin()->memobject_id;
  buf.memobject_size              = ranges.rbegin()->memobject_size;
  buf.memobject_base              = ranges.rbegin()->memobject_base;
  buf.memobject_start_instr_count = ranges.rbegin()->memobject_start_instr_count_icnt;
  buf.memobject_end_instr_count   = ranges.rbegin()->memobject_end_instr_count;
  typename decltype(memobjectfile)::char_type buf[sizeof(trace_memobject_format_t)];
  std::memcpy(buf, &buf_memobject, sizeof(trace_memobject_format_t));
  memobjectfile.write(buf, sizeof(trace_memobject_format_t));
}

VOID FreeObjectBefore(UINT64 addr)
{
  // Simulation Stop
  return (insCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()));
  
  for (unsigned long long i = 0; i < memobject_history.size(); i++)
    {
      if (memobject_history[i].memobject_base == addr && memobject_history[i].memobject_end_instr_count == 0)
      {
            memobject_history[i].memobject_end_instr_count = insCount;
            return;
      }
    }
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
  if (RTN_Name(rtn).find("malloc") != std::string::npos)
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
  else if (RTN_Name(rtn).find("free") != std::string::npos)
  {
    RTN_Open(rtn);

    RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)FreeObjectBefore, 
                IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
                IARG_END);

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
  outfile.close(); 
  memobjectfile.close();

  /* ===================================================================== */
  // Generate Ouput Trace
  /* ===================================================================== */
  tracefile.open(KnobOutputFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!tracefile) {
    std::cout << "Couldn't open output trace file. Exiting." << std::endl;
    exit(1);
  }
  
  // Open instruction trace file for read
  outfile.open(KnobInstrFile.Value().c_str(), std::ios_base::binary | std::ios_base::in);
  if (!outfile) {
    std::cout << "Couldn't open instruction trace file. Exiting." << std::endl;
    exit(1);
  }

  // Open memory object trace file for read
  memobjectfile.open(KnobObjectFile.Value().c_str(), std::ios_base::binary | std::ios_base::in);
  if (!memobjectfile) {
    std::cout << "Couldn't open memory object trace file. No Exiting." << std::endl;
    exit(1);
  }
  
  tracefile.close();
  outfile.close();
  memobjectfile.close();
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

  outfile.open(KnobInstrFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!outfile) {
    std::cout << "Couldn't open instruction trace file. Exiting." << std::endl;
    exit(1);
  }

  memobjectfile.open(KnobObjectFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!memobjectfile) {
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
