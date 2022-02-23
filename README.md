# Dynamic Memory Overflow Detection Using Taint Analysis

### Part 1: Mark user input as tainted (20%)

- Marked tainted bytes from fgets via stdin.
- Marked tainted bytes from gets.
- Marked tainted bytes from command line.

### Part 2: Track how tainted data propagates (20%)

- Tracked byte propagation for strcpy. If src is tainted, marked dest bytes as tainted as well.

### Part 3: Detect if tainted data is used as return address (20%)

### Part 4: Store stack traces for each tainted bytes (30%)

### Part 5: Detail the limitations of the project (10%)
