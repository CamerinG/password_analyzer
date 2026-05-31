# Password Strength Analyzer

A password strength analyzer written in **C** and **x86-64 Assembly Language (NASM)** that evaluates password strength using an entropy-based scoring system.

## Overview

This project estimates the strength of a password by analyzing the character types it contains and calculating an approximate entropy value. Entropy is a common cybersecurity metric used to measure how difficult a password would be to guess through brute-force attacks.

The program examines a user-provided password, determines whether it contains uppercase letters, lowercase letters, numbers, and special characters, and then estimates the size of the possible character set used to create the password. Using this information and the password length, it calculates an entropy value and converts that value into a score from 0 to 100.

The project was intentionally implemented using a combination of C and x86-64 Assembly Language to gain experience with low-level programming concepts, memory management, CPU registers, and cross-language integration.

---

## Features

* Character classification

  * Uppercase letters
  * Lowercase letters
  * Numbers
  * Special characters

* Entropy-based password evaluation

* Strength scoring system (0–100)

* Password grading

  * Weak
  * Moderate
  * Strong

* C and Assembly Language integration

* Floating-point calculations using SSE instructions

---

## How It Works

### Step 1: Character Analysis

The program scans the password one character at a time and determines which character categories are present:

* A-Z
* a-z
* 0-9
* Special symbols

The presence of these categories determines the size of the possible character set.

Example:

```text
Password: Pa$$w0rd

Uppercase: Yes
Lowercase: Yes
Numbers: Yes
Special Characters: Yes
```

This results in a larger possible character space than a password containing only lowercase letters.

---

### Step 2: Entropy Estimation

The program estimates password entropy using:

```text
Entropy ≈ log₂(R × L)
```

Where:

* R = size of the possible character set
* L = password length

Examples:

```text
Lowercase only:
R = 26

Lowercase + Uppercase + Numbers + Symbols:
R = 94
```

To efficiently approximate the logarithm, the assembly implementation uses the processor's **Bit Scan Reverse (BSR)** instruction to identify the most significant bit of the calculated value.

---

### Step 3: Score Calculation

The entropy value is normalized into a score between 0 and 100:

```text
Score = ((Entropy - MinimumEntropy) / EntropyRange) × 100
```

The score is then clamped between 0 and 100 to ensure valid output.

---

### Step 4: Strength Classification

Passwords are classified as:

| Score  | Rating   |
| ------ | -------- |
| 0-39   | Weak     |
| 40-69  | Moderate |
| 70-100 | Strong   |

---

## Example Output

### Strong Password

```text
enter password: #47sldksjfC

Character classification score: 4
Password strength score: 91
Password strength grade: Strong
analyze_password_strength returned: 10
```

### Weak Password

```text
enter password: 123

Character classification score: 1
Password strength score: 0
Password strength grade: Weak
analyze_password_strength returned: 4
```

---

## Technologies Used

* C
* x86-64 Assembly Language (NASM)
* GCC
* Make
* Linux (Kali Linux development environment)

---

## What I Learned

This project provided hands-on experience with:

* Assembly Language programming
* CPU registers and memory management
* Calling conventions between C and Assembly
* Floating-point calculations using SSE instructions
* Debugging segmentation faults
* Password entropy concepts
* Low-level software development
* Build automation using Makefiles

One interesting lesson learned during development was that password entropy depends primarily on the variety of character categories present rather than the number of occurrences of each category. As my understanding of entropy improved, I refined the implementation to better reflect how password strength is evaluated in practice.

---

## Future Improvements

* Implement a true logarithm calculation instead of using a BSR approximation
* Support longer passwords
* Add dictionary-word detection
* Add common password blacklist checks
* Generate password improvement suggestions
* Export results to a file

---

## Building the Project

### Requirements

* GCC
* NASM
* GNU Make

### Build

```bash
make clean
make
```

### Run

```bash
./analyzer_intel
```

---

## Educational Purpose

This project was developed as a systems programming and cybersecurity learning exercise. The goal was to explore how a real-world security concept such as password strength evaluation can be implemented using low-level programming techniques while integrating Assembly Language with a higher-level language such as C.
