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

#ifndef TRACE_MAMOBJECT_H
#define TRACE_MEMOBJECT_H

#include <limits>

#include "trace_instruction.h"

struct trace_instr {
  // instruction pointer or PC (Program Counter)
  unsigned long long ip;
  unsigned long long instr_count;

  // branch info
  unsigned char is_branch;
  unsigned char branch_taken;

  unsigned char destination_registers[NUM_INSTR_DESTINATIONS]; // output registers
  unsigned char source_registers[NUM_INSTR_SOURCES];           // input registers

  unsigned long long destination_memory[NUM_INSTR_DESTINATIONS]; // output memory
  unsigned long long source_memory[NUM_INSTR_SOURCES];           // input memory
};

struct trace_memobject {
    unsigned long long memobject_id;

    unsigned long long memobject_size;
    unsigned long long memobject_base;
    unsigned long long memobject_start_instr_count;
    unsigned long long memobject_end_instr_count;   // invalid if is zero
};

#endif
