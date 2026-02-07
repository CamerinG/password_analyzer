This Password Strength Analyzer (built with C and Assembly) uses low-level programming as well as entropy calculations to demonstrate how security concepts can be implemented close to the hardware. 

Features:
Character classification - i.e. uppercase, lowercase, numeric and special
Strength grade - Weak, Moderate, Strong

Entropy Calculation:
E = log2( R * L) ===> password entropy equation ( R == # of possible characters, L == length of password)

Strength Grading Scores (this was done in C):
Strong >= 70
Moderate >= 40
Weak < 40



Build & Run:
Requirements:
    GCC
    NASM
    Linux (this was tested on kali linux)

to build(in bash):
    make clean
    make
to run:
    ./analyzer_intel

I decided to build this project to gain a better understanding of low-level language, as well as learn a little bit more about cryptography and password security.