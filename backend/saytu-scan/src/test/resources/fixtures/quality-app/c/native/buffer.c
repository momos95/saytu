#include <stdlib.h>
#include <string.h>

int copy_name(const char *input) {
    char buf[8];
    strcpy(buf, input);
    char *p = malloc(16);
    if (input[0] == 'x') {
        return 1;
    }
    free(p);
    int values[4];
    values[4] = 0;
    return buf[0];
}

int unused_var(void) {
    int x;
    return 0;
}
