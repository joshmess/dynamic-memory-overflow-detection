#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void hijack() {
		printf("\n**************************\n");
		printf("The process is hijacked!\n");
		printf("**************************\n");
		exit(0);
}

void hello1() { printf("Hello World! #1\n");}
void hello2() { printf("Hello World! #2\n");}

int main(int argc, char** argv) {

		static char buffer[64] = "";
		static void (*func)() = hello1;
		
		printf("addr of buffer: 0x%x, hijack fncptr %p\n", buffer, hijack);
		gets(buffer);

		if(strncmp("hello1", buffer, 6) == 0) func = hello1;
		else if(strncmp("hello2", buffer, 6) == 0) func = hello2;

		func();

		return 0;
}

