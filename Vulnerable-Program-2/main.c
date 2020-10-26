#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <Windows.h>
#include "md5.h"

#define MIN_REQ_SIZE 32

typedef struct req {
    unsigned char* contents;
    unsigned char md5[16];
} req_t;

void this_is_a_vulnerable_function(size_t size) {
    char buf[10] = { 0 };
    buf[size] = "A";
}

int compare_hashes(unsigned char* a, unsigned char* checksum) {
    int i;
    for (i = 0; i < 16; i++) {
        if (a[i] != checksum[i]) {
            break;
        }
    }
    if (i == 16) {
        return 1;
    }
    else 
        return 0;
}

__declspec(dllexport) int fuzz_target(char* filename);

int fuzz_target(char* filename) {
    // open file 
    FILE* fp;
    errno_t err;
    err = fopen_s(&fp, filename, "r");
    if (err != 0) {
        printf("Error reading file.");
        return 0;
    }

    // determine no of bytes 
    fseek(fp, 0, SEEK_END);
    size_t bytes_count = ftell(fp);
    rewind(fp);

    // verify size of request
    if (bytes_count < MIN_REQ_SIZE) {
        printf("Invalid input.");
        return 0;
    }

    req_t input = { 0 };
    // dynamically allocate memory for file data
    input.contents = malloc(sizeof(unsigned char) * (bytes_count - 15));
    if (input.contents == NULL) {
        fputs("Memory error occured.", stderr);
        return 0;
    }

    memset(input.contents, 0, sizeof(unsigned char) * (bytes_count - 15));
    fread(input.contents, sizeof(unsigned char), bytes_count - 16, fp);
    fread(&input.md5, sizeof(input.md5), 1, fp);

    
    fclose(fp);

    MD5_CTX mdContext;

    // perform md5 hashing 
    MD5Init(&mdContext);
    MD5Update(&mdContext, input.contents, strlen(input.contents));
    MD5Final(&mdContext);
    
    if (compare_hashes(mdContext.digest, input.md5))
        this_is_a_vulnerable_function(0xFFFF);
    else
        printf("Hash value provided is incorrect. Please try again.");
    
    return 0;
}

int main(int argc, char* argv[]) {
	if (argc < 2) {
		printf("Usage: %s <input file>\n", argv[0]);
		return 0;
	}
	return fuzz_target(argv[1]);
}