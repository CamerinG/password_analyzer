CC = gcc
CFLAGS = -Wall -O2 	# Flags passed to gcc, -Wall enables all warnings, -O2 enables optimizations
NASM = nasm 	# Assembler for intel syntax assembly (for password_strength.asm)
NASMFLAGS = -f elf64 	# Flags passed to nasm, -f elf64 specifies output format ie 64-bit ELF object file


# --- Source Files ---
C_SRC = main.c 	# C source files
C_OBJ = main.o 	# C object files
ASM_SRC = analyzer.asm # Assembly source files (Intel syntax) 
ASM_OBJ = analyzer.o  	# Assembly object files (Intel syntax)
EXEC = analyzer_intel 	# Output executable name

all: $(EXEC) 	#So the executable is built with 'make all' or just 'make'

# --- Build Targets ---
$(EXEC): $(C_OBJ) $(ASM_OBJ) 	# -0 2 means to output to the targets name (analyzer_intel)
# -no-pie to disable position independent executable for linking with assembly
	$(CC) -no-pie -o $@ $^ 		

$(C_OBJ): $(C_SRC) #-c tells gcc to compile only, not link -o is output file, $@ is target name(main.o), $< is first prerequisite(main.c)
	$(CC) $(CFLAGS) -c $< -o $@

# Assembly compilation
$(ASM_OBJ): $(ASM_SRC) 	# -o specifies output file, $@ is the target name(analyzer.o), $< is the first prerequisite(analyzer.asm)
	$(NASM) $(NASMFLAGS) -o $@ $<

# clean target to remove compiled files
clean:
	rm -f *.o $(EXEC)