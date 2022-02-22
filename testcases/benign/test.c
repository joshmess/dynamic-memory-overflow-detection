#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int string_copy(char *text) {
		char buffer[36];
		
		printf("buffer = 0x%x, text = %s\n", buffer, text);

		strcpy(buffer, text);
		
		/* do something */
		return 0;
}

int main(int argc, char *argv[]) {
		if(argc < 2) {
				printf("Usage: %s <text>\n", argv[0]);
				exit(0);
		}
		
		int ret = string_copy(argv[1]);

		return ret;
}

