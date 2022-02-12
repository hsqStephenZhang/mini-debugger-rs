#include <stdio.h>

int a = 1;

int func1() {
    a = 2;
    printf("hello world, a=%d\n", a);
    a = 3;
    printf("hello world, a=%d\n", a);
    return 0;
}
