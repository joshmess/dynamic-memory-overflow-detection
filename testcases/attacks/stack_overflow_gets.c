#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int string_copy(char *text) {
		char buffer[36];
		
		printf("buffer = 0x%x\n", buffer);

		strcpy(buffer, text);
		
		/* do something */
		return 0;
}

int main(int argc, char *argv[]) {
				
		char buf[128];
		gets(buf);
		int ret = string_copy(buf);

		return ret;
}

