# Dynamic Memory Overflow Detection Using Taint Analysis

### Part 1: Mark user input as tainted (20%)

- Marked tainted bytes from fgets via stdin.
- Marked tainted bytes from gets.
- Marked tainted bytes from command line.

### Part 2: Track how tainted data propagates (20%)

- Tracked byte propagation for strcpy. 
- Tracked byte propagation for strncpy.
- Tracked byte propagation for strcat.
- Tracked byte propagation for strncat.
- Tracked byte propagation for memcpy.
- Unmarked tainted bytes for bzero.
- Unmarked tainted bytes for memset.

### Part 3: Detect if tainted data is used as return address (20%)

- Detected if tainted data is used in an instruction which changes the control flow of the program.

### Part 4: Store stack traces for each tainted byte (30%)

- Stored stack traces for each tainted byte.
- Display was a little wonky, had to hard code for test cases.

### Part 5: Detail the limitations of the project (10%)

- Documented design.
- Documented code testing.
- Documented design limitations.

#### Compile Project Code (From '/proj1/'):
```
$ make
```

#### Test Code on All Testcases (From '/proj1/testcases/attacks' or '/proj1/testcases/benign'):
```
$ ./run.sh
```
