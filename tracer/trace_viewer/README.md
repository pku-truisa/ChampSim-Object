champsim-object trace viewer 

To use the tracer viewer first compile it using g++:

    g++ trace_viewer.cpp -o trace_viewer

Adding the "-i" flag will print the dissassembly instruction trace
  trace_viewer -i instruciton.trace
Adding the "-m" flag will print the dissassembly object malloc trace
  trace_viewer -m memojbect.trace