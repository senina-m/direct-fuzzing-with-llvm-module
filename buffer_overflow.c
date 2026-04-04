#include <stdio.h>
#include <string.h>

int safe_func() {
    return 2 - 2;
}

void vuln_func(char *input) {
    char buf[16];
    strcpy(buf, input);  // ← уязвимость
}

int main() {
    char input[128] = {0};
    if (!fgets(input, sizeof(input), stdin)) return 0;

    for (int i = 0; i < 128; i++) {
        if (input[i] == '\n') {
            input[i] = '\0';
            break;
        }
    }

    if (input[0] == 'A') {
        return safe_func();
    } else {
        vuln_func(input);
    }

    return 0;
}