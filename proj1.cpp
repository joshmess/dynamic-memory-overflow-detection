#include "pin.H"
#include <iostream>
#include <vector>
#include <stack>
#include <string.h>
#include <string>
#include <unordered_map>
#include <bits/stdc++.h>

#define MAIN "main"
#define FILENO "fileno"

// Taint the memory if the source of input is stdin
#define FGETS "fgets"
#define GETS "gets"

// Propagate if the src is tainted
#define STRCPY "strcpy@plt"
#define STRNCPY "strncpy@plt"
#define STRCAT "strcat@plt"
#define STRNCAT "strncat@plt"
#define MEMCPY "memcpy@plt"

// Reset tainted memory
#define BZERO "bzero@plt"
#define MEMSET "memset@plt"

using namespace std;
using namespace tr1;

// Hashtable to track tainted bytes
unordered_map<unsigned int,unsigned int> taintedBytes;

string int2Hex(unsigned int i){

	stringstream stream;
  	stream << "0x" << std::setfill ('0') << std::setw(sizeof(unsigned int)*2) << std::hex << i;
  	return stream.str();
	
}

unsigned int hex2Int(string hexStr){

	unsigned int toRet;
	stringstream stream;
	stream << std::hex << hexStr;
	stream >> toRet;
	return toRet;

}

VOID addTaintedBytes(unsigned int low, unsigned int up){

	int c =1;
	for(unsigned int i=low;i<=up;i++){
		cout << c << "[TAINTED] " << int2Hex(i) << endl;
		c++;
		taintedBytes[i] = 1;
	}

}

VOID printTaintedBytes(){
	
	int count = 1;	
	unordered_map<unsigned int, unsigned int>::iterator i;
	cout << "--------------------" << endl;
	cout << "Tainted Bytes" << endl;
	cout << "--------------------" << endl;
	for(i = taintedBytes.begin();i != taintedBytes.end();i++){
		if(i->second==1){
			cout << count << "[" << int2Hex(i->first) << "]" << endl;
			count ++;
		}
	}
}

typedef int ( *FP_FILENO )(FILE*);
FP_FILENO org_fileno;

INT32 Usage()
{
	return -1;
}

bool isStdin(FILE *fd)
{
	int ret = org_fileno(fd);
	if(ret == 0) return true;
	return false;
}

bool fgets_stdin = false;
size_t fgets_length = 0;
VOID fgetsTail(char* ret)
{
	if(fgets_stdin) {

		// Get base address as string
        	char baseAddress[32];
        	sprintf(baseAddress,"%p",ret);
        	string bufferBaseAddr = baseAddress;
		unsigned int lowerAddr = hex2Int(bufferBaseAddr);
		unsigned int upperAddr = lowerAddr + fgets_length - 1;		
		
		addTaintedBytes(lowerAddr,upperAddr);		
		//printTaintedBytes();	
	}
	fgets_stdin = false;
}

VOID fgetsHead(char* dest, int size, FILE *stream)
{
	if(isStdin(stream)){	//detects whether src is sdtin
		printf("fgetsHead: dest %p, size %d, stream: stdin)\n", dest, size);
		fgets_stdin = true;
		fgets_length = size;
	} 
}

VOID getsTail(char* dest)
{
	printf("getsTail: dest %p\n", dest);
	printf("size of dest: %d\n", strlen(dest));

	// Get base address as string
       	char baseAddress[32];
       	sprintf(baseAddress,"%p",dest);
       	string bufferBaseAddr = baseAddress;
	
	unsigned int lowerAddr = hex2Int(bufferBaseAddr);
	unsigned int upperAddr = lowerAddr + strlen(dest) - 1;		
	
	addTaintedBytes(lowerAddr,upperAddr);
	//printTaintedBytes();	
}

VOID mainHead(int argc, char** argv)
{
	for(int i=1;i<argc;i++){
		unsigned int lowerAddr, upperAddr;

		char baseAddress[32];
        	sprintf(baseAddress,"%p",argv[i]);
        	string bufferBaseAddr = baseAddress;

		lowerAddr = hex2Int(bufferBaseAddr);
		upperAddr = lowerAddr + strlen(argv[i]) - 1;
		
		addTaintedBytes(lowerAddr,upperAddr);
		//printTaintedBytes();
	}
}

VOID strcpyHead(char* dest, char* src)
{

}

VOID bzeroHead(void* dest, int n)
{

}


VOID Image(IMG img, VOID *v) {
	RTN rtn;

	rtn = RTN_FindByName(img, FGETS);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)fgetsHead, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 2,
		IARG_END);

		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)fgetsTail, 
			IARG_FUNCRET_EXITPOINT_VALUE,
			IARG_END);
			RTN_Close(rtn);
		}

	rtn = RTN_FindByName(img, GETS);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_AFTER, (AFUNPTR)getsTail, 
			//IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCRET_EXITPOINT_VALUE,
		IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, STRCPY);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)strcpyHead, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
		RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, BZERO);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)bzeroHead, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
			RTN_Close(rtn);
	}

	rtn = RTN_FindByName(img, MAIN);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		RTN_InsertCall(rtn, IPOINT_BEFORE, (AFUNPTR)mainHead, 
			IARG_FUNCARG_ENTRYPOINT_VALUE, 0,
			IARG_FUNCARG_ENTRYPOINT_VALUE, 1,
		IARG_END);
		RTN_Close(rtn);
	}


	rtn = RTN_FindByName(img, FILENO);
	if(RTN_Valid(rtn)) {
		RTN_Open(rtn);
		AFUNPTR fptr = RTN_Funptr(rtn);
		org_fileno = (FP_FILENO)(fptr);
		RTN_Close(rtn);
	}
}

int main(int argc, char *argv[])
{
  	PIN_InitSymbols();

	if(PIN_Init(argc, argv)){
		return Usage();
	}
		
 	IMG_AddInstrumentFunction(Image, 0);
	PIN_StartProgram();

	return 0;
}

