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
#include "../../inc/trace_instruction.h"
#include "pin.H"

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_instr_format_t = trace_instr;
using trace_memobject_format_t = trace_memobject;
using input_instr_format_t = input_instr;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 instrCount = 0;
UINT64 memobjCount = 0;

std::ofstream outfile;       // pin instruction trace
std::ofstream memobjectfile; // memory object trace
std::ofstream tracefile;     // champsim-object input trace

trace_instr_format_t curr_instr;
trace_memobject_format_t curr_memobject;

vector<trace_memobject_format_t> memobject_history;

/* ===================================================================== */
// Command line switches
/* ===================================================================== */
KNOB<std::string> KnobTraceFile(KNOB_MODE_WRITEONCE,  "pintool", "o", "champsim-object.trace", "specify file name for Champsim-Object tracer output");
KNOB<std::string> KnobInstrFile(KNOB_MODE_WRITEONCE, "pintool", "i", "champsim_instr.trace", "specify file name for Champsim-Object instruction tracer output");
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
            << "Specify the instruction trace file with -i" << std::endl
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
  curr_instr = {};
  curr_instr.ip = (unsigned long long int)ip;
  curr_instr.instr_count = instrCount;
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
  if (instrCount <= (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())) return;

  trace_memobject_format_t curr_memobject = {};

  curr_memobject.oid                = memobjCount;
  curr_memobject.osize              = (unsigned long long) size;
  curr_memobject.obase              = 0;
  curr_memobject.begin_instr_count  = instrCount; // valid
  curr_memobject.end_instr_count    = 0;          // not free

  memobject_history.push_back(curr_memobject);

  ++memobjCount;
}

VOID AllocObjectAfter(UINT64 ret)
{
  if (instrCount <= (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())) return;

  memobject_history.rbegin()->obase = ret;
}

VOID FreeObjectBefore(UINT64 addr)
{
  if (instrCount <= (KnobTraceInstructions.Value() + KnobSkipInstructions.Value())) return;

  for (unsigned long long i = 0; i < memobject_history.size(); i++)
  {
    // if free address is in-bound and the memory object is not free and not invalid
    if ( memobject_history[i].obase <= addr && (memobject_history[i].obase + memobject_history[i].osize) > addr // find coressponding memory object
      && memobject_history[i].end_instr_count == 0                               // this memory object has not being freed
      && memobject_history[i].begin_instr_count != 0 )                           // this memory object is not invalid
    {
      memobject_history[i].end_instr_count = instrCount;
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
  trace_memobject_format_t buf_memobject = {};

  // write memobject trace into file
  for (unsigned long long i = 0; i < memobject_history.size(); i++)
  {
    buf_memobject.oid                = memobject_history[i].oid;
    buf_memobject.osize              = memobject_history[i].osize;
    buf_memobject.obase              = memobject_history[i].obase;
    buf_memobject.begin_instr_count  = memobject_history[i].begin_instr_count;
    buf_memobject.end_instr_count    = memobject_history[i].end_instr_count;

    typename decltype(memobjectfile)::char_type buf[sizeof(trace_memobject_format_t)];
    std::memcpy(buf, &buf_memobject, sizeof(trace_memobject_format_t));
    memobjectfile.write(buf, sizeof(trace_memobject_format_t));
  }

  memobjectfile.close(); // close memory object trace file
  outfile.close();       // close instruction trace file

  /* ===================================================================== */
  // Generate Ouput Trace File
  /* ===================================================================== */
  
  // Open instruction trace file for read
  FILE* instrfile;
  instrfile = fopen(KnobInstrFile.Value().c_str(), "rb");
  if (!instrfile) {
    std::cout << "Couldn't open instruction trace file. No Exiting." << std::endl;
    exit(1);
  }

  trace_instr_format_t curr_trace_instr;

  while(fread(&curr_trace_instr, sizeof(trace_instr_format_t), 1, instrfile))
  {
      input_instr_format_t buf_instr = {};

      buf_instr.ip = curr_trace_instr.ip;
      buf_instr.is_branch = curr_trace_instr.is_branch;

      for(unsigned long long i = 0; i < NUM_INSTR_DESTINATIONS; i++) 
      {
        buf_instr.destination_registers[i] = curr_trace_instr.destination_registers[i];
        buf_instr.destination_memory[i] = curr_trace_instr.destination_memory[i];
      }

      for(unsigned long long i = 0; i < NUM_INSTR_SOURCES ;i++)
      {
        buf_instr.source_registers[i] = curr_trace_instr.source_registers[i];
        buf_instr.source_memory[i] = curr_trace_instr.source_memory[i];
      }

      for(unsigned long long i = 0; i < NUM_INSTR_DESTINATIONS; i++){
          for(auto memobj: memobject_history){
              if(  (curr_trace_instr.instr_count >= memobj.begin_instr_count && memobj.begin_instr_count != 0)
                && (curr_trace_instr.instr_count <= memobj.end_instr_count || memobj.end_instr_count == 0 )
                && curr_trace_instr.destination_memory[i] >= memobj.obase 
                && curr_trace_instr.destination_memory[i] < memobj.obase + memobj.osize )
              {
                buf_instr.destination_oid[i] = memobj.oid;
                buf_instr.destination_obase[i] = memobj.obase;
                buf_instr.destination_obound[i] = memobj.obase + memobj.osize - 1;
                break;
              }
          }
      }
      for(unsigned long long i = 0; i < NUM_INSTR_SOURCES;i++){
          for(auto memobj: memobject_history){
              if(  (curr_trace_instr.instr_count >= memobj.begin_instr_count && memobj.begin_instr_count != 0)
                && (curr_trace_instr.instr_count <= memobj.end_instr_count || memobj.end_instr_count == 0 )
                && curr_trace_instr.source_memory[i] >= memobj.obase 
                && curr_trace_instr.source_memory[i] < memobj.obase + memobj.osize )
              {
                buf_instr.source_oid[i] = memobj.oid;
                buf_instr.source_obase[i] = memobj.obase;
                buf_instr.source_obound[i] = memobj.obase + memobj.osize - 1;
                break;
              }
          }
      }
      
      typename decltype(tracefile)::char_type buf[sizeof(input_instr)];
      memcpy(buf, &buf_instr, sizeof(input_instr));
      tracefile.write(buf, sizeof(input_instr));
  }

  fclose(instrfile);

  tracefile.close();
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

  tracefile.open(KnobTraceFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!tracefile) {
    std::cout << "Couldn't open output trace file. Exiting." << std::endl;
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
