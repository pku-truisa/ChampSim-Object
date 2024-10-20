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

struct input_memobject {
  unsigned long long oid;               // Memory ObjectID
  unsigned long long obase;             // Memory Objecct Base Address
  unsigned long long osize;             // Memory Object Size

  unsigned long long timestamp;         // the Time After Malloc()
};

#endif
