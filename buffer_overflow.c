/* #include <stdio.h>
#include <string.h>

int safe_func() {
    return 2 + 1;
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
        int y = safe_func();
        if (y == 3){
            return 0;
        }
    } else {
        vuln_func(input);
    }

    return 0;
}
*/

 // Транзитивные вызовы

#include <string.h>

void do_something(char* data) {
    data[0] = 0;
}


void inner(char *data) {
    char buf[5];
    do_something(buf);
    strcpy(buf, data);  // уязвимость
}

void middle(char *data) {
    inner(data);  // вызывает уязвимую
}

void outer() {
    middle("exploit");  // вызывает middle
}

void safe() {
    int x = 0;
}

int main(int argc, char** argv) {
    // safe();
    // if (argv[0] == "A") {char buf[5]; do_something(buf); return 0;}
    // if (argv[0] == "B") { safe(); return 0;}
    // if (argv[0] == 1) outer();
    if (argv[0] == "A") return 0;
    else inner("exploit");
    // else safe();
    return 0;
}


/* // Косвенный вызов (Function Pointer)

#include <stdio.h>
#include <string.h>

void trigger_vulnerability(char *input) {
    char buf[8];
    strcpy(buf, input);
}

int main() {
    char input[128] = {0};
    if (fgets(input, sizeof(input), stdin) == NULL) return 0;  // ← этот блок

    if (input[0] != 'A') return 0;  // ← этот блок
    if (input[1] != 'B') input[1] = 'C';

    trigger_vulnerability(input);
    return 0;
}

 */


/* //Косвенный вызов (Function Pointer) 
typedef void (*callback_t)(int);

void vulnerable_func(int x) {
    char buf[10];
    strcpy(buf, "very_long_string"); // Уязвимость здесь
}

void safe_wrapper(callback_t cb) {
    cb(10); // Косвенный вызов!
}

int main() {
    safe_wrapper(vulnerable_func);
    return 0;
}
*/