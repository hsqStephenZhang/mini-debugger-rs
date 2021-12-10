#include <stdio.h>

void f1(){

}

int f2(){
    return 1;
}

int main(){
    int a=1;
    int b=2;
    int c=a+b;
    printf("%d\n",c);
    c=4;
    printf("%d\n",c);
    c=5;
    printf("%d\n",c);
    f1();
    c=f2();
    printf("%d\n",c);
}
