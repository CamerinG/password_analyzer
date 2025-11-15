This project is a password strength analyzer written in C and x86‑64 assembly. It calculates password entropy based on length and character diversity, then outputs a strength score (0-100) and grade(weak, moderate, strong).

My goals for this project were to:

- Deepen my understanding of low‑level programming and the compilation process.

- Explore how to combine C and assembly in a single program.

- Apply cybersecurity principles to a practical use.

---------BUILD AND RUN------

in Bash:
make clean
make
./analyzer_intel 

enter a password

program will output:
character classification score
password strength score
password grade

-----------Thoughts and Ramblings--------------------

I wanted to learn more about c and assembly, I also wanted to try to combine them and 'interrupt' the compilation in order to make multiple languages work together in one executable file. I felt that it was a good project for me to dive a little bit deeper into low level coding. I chose to do a password analyzer because I'm also very interested in cyber security, I'm really glad that I chose this as well because I learned a lot more about passwords and the math behind them. I commented most of my lines because I felt that it really helped cement in my head what was happening in the code. 

This password analyzer takes a password and calculates its entropy based on the length and types of characters used (There is more detail on this inside the note in the actual program). While it's not the most sophisticated password program that exists I believe it was an amazing program to learn from. 

--------------------------------------------------------
