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
#include <unordered_map>
#include <algorithm>

#include "../../inc/trace_memobject.h"
#include "../../inc/trace_instruction.h"
#include "pin.H"

/* ===================================================================== */
/* Names of malloc and free */
/* ===================================================================== */
#if defined(TARGET_MAC)
#define MALLOC "_malloc"
#else
#define MALLOC "malloc"
#endif

using std::cerr;
using std::endl;
using std::string;
using std::vector;

using trace_memobject_format_t = input_memobject;
using trace_instr_format_t = input_instr;

/* ================================================================== */
// Global variables
/* ================================================================== */

UINT64 instrCount = 0;
UINT64 memobjCount = 0;

std::ofstream outfile;       // pin instruction trace
std::ofstream memobjectfile; // memory object trace

trace_instr_format_t curr_instr;
trace_memobject_format_t curr_memobject;

// forward declare free handler so Routine can reference it before its definition
VOID FreeObjectBefore(UINT64 ptr);

// lock to protect memobject file writes and alloc_map
PIN_LOCK memfile_lock;

// meta info stored for each allocation so we can update the allocation record on free
struct alloc_meta_t {
  unsigned long long oid;
  std::streampos file_offset;
  unsigned long long osize;
  unsigned long long timestamp;
};

std::unordered_map<unsigned long long, alloc_meta_t> alloc_map;

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
  curr_memobject       = {};
  curr_memobject.osize = (unsigned long long)size;
  curr_memobject.free_timestamp = 0;
}

VOID AllocObjectAfter(UINT64 ret)
{
  curr_memobject.obase     = (unsigned long long)ret;
  curr_memobject.timestamp = (unsigned long long)instrCount;
  curr_memobject.free_timestamp = 0;

  if (instrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()))
    return;

  // write allocation record immediately and record file offset for later update on free
  PIN_GetLock(&memfile_lock, 1);
  unsigned long long assigned_oid = memobjCount++;
  curr_memobject.oid = assigned_oid;

  std::streampos rec_offset = memobjectfile.tellp();
  typename decltype(memobjectfile)::char_type buf_obj[sizeof(trace_memobject_format_t)];
  std::memcpy(buf_obj, &curr_memobject, sizeof(trace_memobject_format_t));
  memobjectfile.write(buf_obj, sizeof(trace_memobject_format_t));

  alloc_meta_t meta;
  meta.oid = assigned_oid;
  meta.file_offset = rec_offset;
  meta.osize = curr_memobject.osize;
  meta.timestamp = curr_memobject.timestamp;
  alloc_map[curr_memobject.obase] = meta;

  // release lock
  PIN_ReleaseLock(&memfile_lock);
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
  string freename("free");

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
  memobjectfile.close(); // close memory object trace file
  outfile.close();       // close instruction trace file
}

// Called before free(ptr) is executed
VOID FreeObjectBefore(UINT64 ptr)
{
  // only consider frees within tracing window
  if (instrCount > (KnobTraceInstructions.Value() + KnobSkipInstructions.Value()))
    return;

  PIN_GetLock(&memfile_lock, 1);

  auto it = alloc_map.find((unsigned long long)ptr);
  if (it != alloc_map.end()) {
    // prepare updated allocation record with free_timestamp
    trace_memobject_format_t alloc_rec = {};
    alloc_rec.oid = it->second.oid;
    alloc_rec.obase = (unsigned long long)ptr;
    alloc_rec.osize = it->second.osize;
    alloc_rec.timestamp = it->second.timestamp;
    alloc_rec.free_timestamp = (unsigned long long)instrCount;

    // seek and overwrite the allocation record
    memobjectfile.seekp(it->second.file_offset, std::ios::beg);
    typename decltype(memobjectfile)::char_type buf_alloc[sizeof(trace_memobject_format_t)];
    std::memcpy(buf_alloc, &alloc_rec, sizeof(trace_memobject_format_t));
    memobjectfile.write(buf_alloc, sizeof(trace_memobject_format_t));

    // move write pointer back to end for future appends
    memobjectfile.seekp(0, std::ios::end);

    // remove mapping (freed)
    alloc_map.erase(it);
    PIN_ReleaseLock(&memfile_lock);
    return;
  }
  // no matching allocation recorded; do not append a free-only record per request
  PIN_ReleaseLock(&memfile_lock);
  return;
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

  memobjectfile.open(KnobObjectFile.Value().c_str(), std::ios_base::binary | std::ios_base::trunc);
  if (!memobjectfile) {
    std::cout << "Couldn't open memory object trace file. Exiting." << std::endl;
    exit(1);
  }

  // initialize lock for memobject file and alloc_map
  PIN_InitLock(&memfile_lock);

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
