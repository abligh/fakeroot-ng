#ifndef PROCESS_H
#define PROCESS_H

// Bitmasks to be stored in context_state[0] by all functions handling new process creation
#define NEW_PROCESS_SAME_PARENT         0x01
#define NEW_PROCESS_SAME_VM             0x02
#define NEW_PROCESS_SAME_FD             0x04
#define NEW_PROCESS_SAME_ROOT           0x08
#define NEW_PROCESS_SAME_DEBUGGER       0x10

#endif // PROCESS_H
