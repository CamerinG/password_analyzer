#include <stdio.h>
#include <string.h>

#define MAX_PASSWORD_LENGTH 15
#define MIN_PASSWORD_LENGTH 3

char password[MAX_PASSWORD_LENGTH + 1];

extern int classify_characters(const char *password, int length);
extern int analyze_password_strength(const char *password, int length);
extern int score_strength(const char *password, int length);

int main() {

    printf("enter password: ");

    fgets(password, sizeof(password), stdin);

    int length = strlen(password);

    // Remove newline character if present
    if (length > 1 && password[length - 1] == '\n') {
        password[length - 1] = '\0';
        length--;
    }

    if(length < MIN_PASSWORD_LENGTH || length > MAX_PASSWORD_LENGTH) {
        printf("Password length must be between %d and %d characters.\n", MIN_PASSWORD_LENGTH, MAX_PASSWORD_LENGTH);
        return 1;
    }

    int char_score = classify_characters(password, length);
    int score = score_strength(password, length);
    int strength = analyze_password_strength(password, length);

    const char *grade;
    if (score >= 70) {
        grade = "Strong";
    } else if (score >= 40) {
        grade = "Moderate";
    } else {
        grade = "Weak";
    }
    
    printf("Character classification score: %d\n", char_score);
    printf("Password strength score: %d\n", score);
    printf("Password strength grade: %s\n", grade);
    printf("analyze_password_strength returned: %d\n", strength);

    return 0;
}