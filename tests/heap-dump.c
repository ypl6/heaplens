/* Demo script for heap dump.*/

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void foo()
{
    void* p3 = malloc(0x10);
    memset(p3, 'C', 0x10);
}

void breakme()
{
    printf("Breakpoint at me to check out the heap!\n");
}

int main(int argc, char** argv, char** envp)
{
        void* p1 = malloc(0x10);
        void* p2 = calloc(0x20, 1);
        memset(p1, 'A', 0x10);
        memset(p2, 'B', 0x20);
        p1 = realloc(p1, 0x30);
        free(p2);
        foo();

        breakme();
        return EXIT_SUCCESS;
}