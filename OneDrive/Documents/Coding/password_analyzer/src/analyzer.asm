section .text
global classify_characters
global analyze_password_strength
global score_strength

section .bss
    uppercase_count    resq 1
    lowercase_count    resq 1
    numeric_count      resq 1
    special_count      resq 1
    entropy_value      resq 1

section .data
    range_entropy: dd 5.6        ; 5.6 is the difference of the maximum and minimum score log2( 94 * 15) = 10.5 (max) and log2( 10 * 3) = 4.9 (min)
    min_entropy: dd 4.9          ; 4.9 is our min entropy
    score_scale: dd 100.0
    zero_float: dd 0.0

classify_characters:
    xor rcx, rcx       ; initialize a register as a loop counter (length of password)
    xor rax, rax       ; initialize a counter for uppercase classify_characters
    xor rbx, rbx       ; initialize a counter for the special characters
    xor r8, r8        ; initialize the lower case counter
    xor r9, r9        ; initialize the numeric counter

.loop_start:
    cmp rcx, rsi      ; compare the loop counter to the password length 
    jge .done_classify           ; once the loop counter meets the length of the password we jump to .done
    movzx rdx, byte [rdi + rcx] ; movzx (move zero extend) - reads smaller value and fills upper bits with zeros, rdi points to the password and rcx points to the index, rdi holds the pointer to the password string

    cmp rdx, 65        ; compare the current character with 'A' (ASCII A = 65)
    jl .not_uppercase   ; if rdx is less than 65 (A) jump to .not_uppercase
    cmp rdx, 90        ; compare rdx to 90 (Z)
    jg .not_uppercase   ; jump to .not_uppercase if rdx is greater than 90
    inc rax            ; increment the uppercase counter
    jmp .continue_loop

.not_uppercase:         ; we have ruled out uppercase characters, now we will determine if it is lowercase
    cmp rdx, 97        ; compare current character to 97 (a)
    jl .not_alpha 
    cmp rdx, 122       ; now we want to see where rdx is compared to 122(z)
    jg .not_alpha
    inc r8 
    jmp .continue_loop

.not_alpha: ; we will check to see if the character is numeric
    cmp rdx, 48        ; 48 is == ASCII 0
    jl .not_numeric     ; if it is less than 0 then it is not numeric and we know its not alpha as well from the previous functions, so it has to be a special character
    cmp rdx, 57 
    jg .not_numeric
    inc r9
    jmp .continue_loop

.not_numeric:           ; we have now ruled out alphanumeric characters completely we know that the character at the current index must be a special character
    inc rbx            ; increment the special character counter


.continue_loop:
    inc rcx            ; increments the loop counter rcx which makes the loop index move to the next character
    jmp .loop_start     ; and go back to the start of the loop 

.done_classify:
    mov qword [uppercase_count], rax        ; move from this register(rax) to this variable(uppercase_count)
    mov qword [lowercase_count], r8
    mov qword [numeric_count],   r9
    mov qword [special_count],   rbx
    mov qword [entropy_value],   0      
    
    xor rax, rax    ;resetting register to 0 to count character categories
    cmp qword [uppercase_count], 0 
    je .count_lowercase
    inc rax

.count_lowercase:
    cmp qword [lowercase_count], 0
    je .count_numbers
    inc rax

.count_numbers:
    cmp qword [numeric_count], 0
    je .count_special
    inc rax

.count_special:
    cmp qword [special_count], 0 
    je .ret 
    inc rax

.ret:
    ret

;NOTE: in learning more about this program i am creating I have learned that
; creating a score for the strength of the password relies on an equation for password entropy
; as I learned more about this equation I have learned two big lessons
; 1. all that matters is that letters, numbers, and special characters are in the password, not the amount of them
; this means that all the code i made above to count all of that is not completely necessary
; this is because simply having the differences in characters increases the number of possibilities for what the password could be
; i will go into more detail about this in the readme
; 2. thinking ahead about the program you are creating could save code
; however jumping right into this did teach me a lot and I'm glad i did
; i will not be editing the code above simply because it made me think about how to create this function in assembly
; and I really enjoyed doing so. 

; E = log2( R * L) ===> password entropy equation ( R == # of possible characters, L == length of password)

analyze_password_strength:
    mov rax, qword [uppercase_count]  ; restore all counts
    mov r8,  qword [lowercase_count]
    mov r9,  qword [numeric_count]
    mov rbx, qword [special_count]
    mov rcx, rsi      ; rcx = password length, rsi = password
    xor r10, r10     ; number of possible characters 

    cmp rax, 0     ; check to see if there is at least 1 uppercase character
    je .check_lowercase     ; if there are no uppercase characters go directly to check if there are lowercase characters
    add r10, 26        ; if there is at least 1 uppercase then you add the number of possible uppercase characters to the equation (R)

.check_lowercase:
    cmp r8, 0      ; check to see if there is 1 lowercase
    je .check_numeric
    add r10, 26

.check_numeric:
    cmp r9, 0      ; check to see if there is at least 1 number
    je .check_special_characters
    add r10, 10

.check_special_characters:
    cmp rbx, 0     ; check to see if there is at least 1 special character
    je .log_r_times_l
    add r10, 32        ; there are 32 possible special character options
    
.log_r_times_l:
    cmp r10, 0          ; if theres no password theres no calculating (no point)
    je .entropy_zero
    imul rcx, r10     ; this is the ( R * L ) portion of the equation
    bsr r11, rcx      ; by finding the most significant bit we can approximate the log2 of our outcome
    jmp .done_entropy

.entropy_zero:
    xor r11, r11

.done_entropy:
    mov qword [entropy_value], r11   ; store computed entropy
    mov rax, r11               ; return entropy value for debug visibility
    ret

;Now we have our entropy(r11), but we still need to make it scorable
; we will take the maximum possible value and subtract the minimum possible entropy value, this will be our denominator
; then we will subtract the minimum possible score from our entropy score (r11) this will be the numerator
; after we divide our numerator by the denominator we can multiply it by 100
; this will give our score a possible range of 0 to 100


score_strength:
    mov r11, qword [entropy_value]   ; load previously computed entropy
    cvtsi2ss xmm1, r11  ; converts integer to scalar single precision (32bit floating point)

    movss xmm0, [min_entropy]     ; loading a 32 bit register with the value of x 
    subss xmm1, xmm0    ; find the difference of the users pswd entropy and the minimum entropy
    
    movss xmm0, [range_entropy]     
    divss xmm1, xmm0    ; divide the outcome of the numerator with the denominator
    
    movss xmm2, [score_scale]   ; the score will be scaled out of 100
    mulss  xmm1, xmm2 ; multiply by 100 to get a score out of 100

    movss xmm0, [zero_float]
    maxss xmm1, xmm0                ;this compares the outcome in xmm1 to our zero_float (0.0) if xmm1 is less than 0 then 0 will be our lower bound
    movss xmm0, [score_scale]       ; score_scale = 100, loads into xmm0
    minss xmm1, xmm0                ;compares score with 100 so if it is over 100, our score will be upper bound to 100

    cvttss2si rax, xmm1             ; rax will store our final score result

    ret