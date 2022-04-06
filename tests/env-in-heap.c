/*
    Demo script for `list-env-in-heap` and heap grooming. 

    
    The environment variable ENV_IN_HEAP will be stored and freed in
    the heap, which affects the heap layout. `list-env-in-heap` can identify
    the environment variable automatically. 
    
    This script contains a simple heap overflow at p4 (line 39). Alter ENV_IN_HEAP
    to see the effect on the heap. To overwrite p3 chunk(BBBB...), set ENV_IN_HEAP
    to the following (length):

        ENV_IN_HEAP=XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

    This will cause the overflow chunk p4 to be placed right before p3.
*/
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

void breakme()
{
    printf("Breakpoint at me to check out the heap!\n");
}

int main(int argc, char** argv, char** envp)
{
    void* p1 = malloc(0x10);
    memset(p1, 'A', 0x10);

    char *env_var1 = getenv("ENV_IN_HEAP");
    char *p2;
    if (env_var1 != NULL){
        size_t size = strlen(env_var1);
        p2 = (char *) malloc(size);
        memcpy(p2, env_var1, size);
    }

    void* p3 = malloc(0x10);
    memset(p3, 'B', 0x10);

    // Free a chunk with size of the envirnoment variable ENV_IN_HEAP.
    if (env_var1 != NULL){
        free(p2);
    }

    void* p4 = malloc(0x60);
    void* p5 = malloc(0x60); // Prevent overflowing top chunk
    memset(p4, 'C', 0x75);  // Simple heap overflow
    memset(p5, 'D', 0x60);
    
    printf("%s\n", (char *) p3);
    breakme();
    return 0;
}