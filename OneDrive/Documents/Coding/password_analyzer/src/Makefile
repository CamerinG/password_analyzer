#== Compiler and Tools ==
CC = gcc
CFLAGS = -Wall -O2 # Flags passed to gcc, -Wall enables all warnings, -O2 enables optimizations
NASM = nasm # Assembler for intel syntax assembly (for password_strength.asm)
NASMFLAGS = -f elf64 # Flags passed to nasm, -f elf64 specifies output format ie 64-bit ELF object file
AS = as # Assembler for AT&T syntax assembly (for password_strength.s)


#== Source Files ==
C_SRC = main.c # C source files
C_OBJ = main.o # C object files
HEADER = analyzer.h # Header files
ASM_INTEL_SRC = analyzer.asm # Assembly source files (Intel syntax)
ASM_INTEL_OBJ = analyzer.o # Assembly object files (Intel syntax)
ASM_ATT_SRC = analyzer2.s # Assembly source files (AT&T syntax)
ASM_ATT_OBJ = analyzer2.o # Assembly object files (AT&T syntax)

#== Output Executable ==
EXEC_INTEL = analyzer_intel # Output executable name for Intel syntax assembly
EXEC_ATT = analyzer_att # Output executable name for AT&T syntax assembly

#== Build Targets ==
all: analyzer_intel #$(EXEC_INTEL) $(EXEC_ATT) #So both executables are built with 'make all' or just 'make'

# Intel Syntax Assembly Build (NASM)
$(EXEC_INTEL): $(C_OBJ) $(ASM_INTEL_OBJ) # -0 2 means to output to the targets name (analyzer_intel)
	$(CC) -no-pie -o $@ $^  

$(ASM_INTEL_OBJ): $(ASM_INTEL_SRC) # -o specifies output file, $@ is the target name(analyzer2.o), $< is the first prerequisite(analyzer2.asm)
	$(NASM) $(NASMFLAGS) -o $@ $<

# AT&T Syntax Assembly Build (GNU Assembler)
$(ASM_ATT_OBJ): $(ASM_ATT_SRC) # -o specifies output file, $@ is the target name(analyzer.o), $< is the first prerequisite(analyzer.s)
	$(AS) -o $@ $<

# Compilation
$(C_OBJ): $(C_SRC) $(HEADER) # -c tells gcc to compile only, not link
	$(CC) $(CFLAGS) -c $< -o $@ 

# clean target to remove compiled files
clean:
	rm -f *.o $(EXEC_INTEL) $(EXEC_ATT)