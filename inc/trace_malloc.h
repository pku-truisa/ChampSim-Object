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

#ifndef TRACE_MALLOC_H
#define TRACE_MALLOC_H

#include <limits>

struct unmap_object{
    unsigned long long malloc_count;
    unsigned long long malloc_end_instr_count;
};
using remap_info = unmap_object;

struct malloc_object {
  // Malloc Counter
    unsigned long long malloc_count;

    unsigned long long malloc_size;
    unsigned long long malloc_base;
    unsigned long long malloc_bound;
    unsigned long long malloc_start_instr_count;
    unsigned long long malloc_end_instr_count;
    unsigned long long malloc_object_valid;      // Clear by free()
};

#endif
