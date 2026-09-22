#include <stdio.h>

int main(void) {
    FILE *f = fopen("/etc/xuanix-logo", "r");
    if (!f) return 1;
    char buf[4096];
    while (fgets(buf, sizeof(buf), f)) {
        fputs(buf, stdout);
    }
    fclose(f);
    return 0;
}
