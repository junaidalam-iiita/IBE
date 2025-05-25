/* This Header File Contains some basic and general puprose utility functions - which make the use of the PBC Libraray and the OpenSSL Libraray easyier. 
The functions are not specific for any particular pairing based protocol like IBE, or, BLS-Signature, or CLPKC etc.
The functions in this libraray are classified in three categories, viz., 1) general purpose utility functions, 2) PBC Libraray Related Utility Functions, and 3) Customized OpenSSL functions.
Decsription of each of these functions are given below. */
#include <pbc/pbc.h>
#include <pbc/pbc_test.h>
#include <openssl/sha.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

pairing_t global_params; // PBC Pairing Parameters - intialized in main() 

/**** Prototype of the Functions ***/

/*       GENERAL PURPOSE UTILITY FUNCTIONS       */

void handleErrors(char * errpoint); 
/*  Function that reports an error. */

void xor_bytes(unsigned char *out, const unsigned char *a, const unsigned char *b, size_t len); 
/* Function to perform bitwise XOR between two strings */

void H0(unsigned char *outstr, int outstr_len, unsigned char *instr, int instr_len); 
/* Random Oracle Hash Function H0: {0,1}^* --> {0,1}^n .
Maps a string of any length to a randomized string of n ('outstr_len') bytes length. 
THIS FUNCTION WAS PREVIOUSLY NAMED 'Expand_String'*/


/*            PBC LIBRARAY RELATED UTILITY FUNCTIONS         */

void myPBC_Initialize();
/* Function to initialize the PBC Libraray. 
Sets the PBC Global Paramerts ('global_params') as per the specified PBC's Parameters File. */

void save_element_to_file(element_t X, FILE * fptr);
/* Function to save a given PBC element ('element_t') X into a given binary file.
NOTE: - We assume that when this function is called, the file-cursor is at correct position,
i.e., the element will be stored in the position where the  file-cursor is currently positioned (does not matter when to store only one varaible into the file). */

void read_element_from_file(element_t X, FILE * fptr);
/* Function to read from a specified file to an 'element_t' variable X.
IMPORTANT: Don't forget to initialize the varaible 'X' (using the PBC element_init_  function) before calling this function. 
NOTE: - We assume that when this function is called, the file-cursor is at correct position,
i.e., it is at the begining of the varaible we want to read (does not matter when the file stores only one varaible). */


/*           MY CUSTOMIZED OPENSSL FUNCTIONS          */

void MyAES_128_ECB_Encr(FILE *input_file, unsigned char *key);
/*  My Customized OpenSSL AES-128 (in ECB Mode)  Encryption Function
- just takes the pointer to the data file and the symmetric-key 
- output is written to 'ciphertext.bin' 
NO NEED TO UNDERSTAND THE IMPLEMENTATAION */

void MyAES_128_ECB_Decr(FILE *input_file, unsigned char *key);
/*  My Customized OpenSSL AES-128 (in ECB Mode)  Decryption Function
- just takes the pointer to the data file and the symmetric-key 
- output is written to 'output.jpeg' (assuming the data-file was a JPEG file) 
NO NEED TO UNDERSTAND THE IMPLEMENTATAION */



//////////////////////////////////////////////////////////////////////////////////////////////////////////

/*            **********    Implementations of the 'SM_PBC_utils.h' Functions  *****          */

/* IMPLEMENTATION of handleErrors()  */

void handleErrors(char * errpoint) {
    fprintf(stderr, "An error occurred. Location: %s\n", errpoint);
    ERR_print_errors_fp(stderr);
    exit(1);
}

/* IMPLEMENTATION of xor_bytes()  */

void xor_bytes(unsigned char *out, const unsigned char *a, const unsigned char *b, size_t len) {
    for (size_t i = 0; i < len; i++) {
        out[i] = a[i] ^ b[i];
    }
}

/* IMPLEMENTATION of H0()
- This algo. is similar to the Key-Material Calculation from Master-Secret in SSL Protocol (see Book) 
- we repeatatively call SHA - each time the given input string ('instr') is appended with a diffrenet 'byte'
- the successive 'bytes' are the ASCII values of 'A', 'B', 'C' etc.
- repeat the loop until the output of required length has been produced */

void H0(unsigned char *outstr, int outstr_len, unsigned char *instr, int instr_len) {
    int i, len, k=0;
    char c = 'A';
    len = instr_len + 1;
    unsigned char *buffer = malloc(SHA256_DIGEST_LENGTH);
    unsigned char *input_to_SHA = malloc(len);

    while (1) {
        for (i = 0; i < (len - 1); i++) {
            input_to_SHA[i] = instr[i];
        }
        input_to_SHA[i] = c++;

        SHA256(input_to_SHA, len, buffer);

        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
            outstr[k++] = buffer[i];
            if (k == outstr_len) {
                free(buffer);
                free(input_to_SHA);
                return;
            }
        }
    }
}

/* IMPLEMENTATION of myPBC_Initialize()  */

void myPBC_Initialize(){
/* The  'pbc_demo_pairing_init()' function was designed to take the PBC params file-path from the command line argument. Thus by-default, it expects the 2nd and its 3rd arguments as
'argc' and 'argv'. It then checks whether 'argc' is greater than 1 or not (i.e., at-least one command line argument is given) and
then takes the 'argv[1]' as the params-file-path.
Now, since we are passing the params-file-path hard-coded from the main() function by calling this function - we are mimicking the 'argv' with an array called 'arr' where,
we place the  params-file-path as it's 2nd item. */
	FILE * parampath_file;
	char ** arr = NULL;
	char param_path[1000];
    	int size = 0;  // Number of elements in the array
   	int capacity = 0;  // Capacity of the array
   	
   	/* Read the params file path from 'parampath.txt' */
	parampath_file = fopen("parampath.txt", "r");
	if(parampath_file == NULL){
	   printf("Error: Couldn't open 'parampath.txt' file!\n");
	   exit(1);
	}
	fgets(param_path, 1000, parampath_file);
	size_t len = strlen(param_path);
        if (len > 0 && param_path[len - 1] == '\n') {
            param_path[len - 1] = '\0';
        }
	
	// Function to add a string to the array
	    	void addString(char *newString) {
			if (size == capacity) {
			    // Increase the capacity of the array
			    capacity = (capacity == 0) ? 1 : capacity * 2;
			    arr = realloc(arr, capacity * sizeof(char *));
			}
			// Allocate memory for the new string and copy it to the array
			arr[size] = malloc(strlen(newString) + 1);
			strcpy(arr[size], newString);
			size++;
	    	}

    	// Add the given param_path as the 2nd item in the array
    	addString(" ");
    	addString(param_path);
    	
    	//Initialize the PBC Libraray Global Parameters as per the specified PBC-params-file
    	pbc_demo_pairing_init(global_params, 2, arr);  // Note: the 2nd argument we manually setting to '2' as it mimicks 'argc' which should be greaer than '1'
    	fclose(parampath_file);
}

/* IMPLEMENTATION of save_element_to_file()  */

void save_element_to_file(element_t X, FILE * fptr){
	size_t element_size = element_length_in_bytes(X);
	unsigned char * element_bin = (unsigned char *) malloc(element_size);
    	element_to_bytes(element_bin, X);
    	size_t retcode = fwrite( element_bin, 1, element_size, fptr);
    	if(retcode == 0){
    		printf("Error while saving element into the file!\n");
    		exit(1);
    	}
    	free(element_bin);
}

/* IMPLEMENTATION of read_element_from_file() */

void read_element_from_file(element_t X, FILE * fptr){
    	size_t element_size = element_length_in_bytes(X); // NOTE: Here you'll not get the correct size if 'X' is not already initialized (before passing into this function).
    	unsigned char * element_bin = (unsigned char *) malloc(element_size);
    	size_t retcode =fread(element_bin, 1, element_size, fptr);
    	if(retcode == 0){
    		printf("Error while reading from file!\n");
    		exit(1);
    	}
    	element_from_bytes(X, element_bin);
}

/* IMPLEMENTATION of MyAES_128_ECB_Encr()  */

void MyAES_128_ECB_Encr(FILE *input_file, unsigned char *key) {
	    // Create and Open output file
	    FILE *output_file = fopen("ciphertext.bin", "wb");
	    if (!output_file) {
		perror("fopen");
		fclose(input_file);
		exit(1);
	    }

	    // Create and initialize the context
	    EVP_CIPHER_CTX *ctx;
	    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Function: MyAES_128_ECB_Encr");
	    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handleErrors("Function: MyAES_128_ECB_Encr");

	    // Buffer for reading file and for ciphertext
	    unsigned char buffer[1024];
	    unsigned char ciphertext[1024 + EVP_CIPHER_block_size(EVP_aes_128_ecb())];
	    int bytes_read, ciphertext_len, len;

	    // Read from input file, encrypt, and write to output file
	    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
		if (1 != EVP_EncryptUpdate(ctx, ciphertext, &len, buffer, bytes_read))
		    handleErrors("Function: MyAES_128_ECB_Encr");
		ciphertext_len = len;
		if (fwrite(ciphertext, 1, ciphertext_len, output_file) != ciphertext_len) {
		    perror("fwrite");
		    fclose(input_file);
		    fclose(output_file);
		    exit(1);
		}
	    }

	    // Finalize encryption
	    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext, &len)) handleErrors("Function: MyAES_128_ECB_Encr");
	    ciphertext_len = len;
	    if (fwrite(ciphertext, 1, ciphertext_len, output_file) != ciphertext_len) {
		perror("fwrite");
		fclose(input_file);
		fclose(output_file);
		exit(1);
	    }

	    // Clean up
	    EVP_CIPHER_CTX_free(ctx);
	    fclose(output_file);

	    printf("File encrypted successfully and written to 'ciphertext.bin'\n");
}

/* IMPLEMENTATION of MyAES_128_ECB_Decr()  */

void MyAES_128_ECB_Decr(FILE *input_file, unsigned char *key) {
	    // Open output file
	    FILE *output_file = fopen("output.jpeg", "wb");
	    if (!output_file) {
		perror("fopen");
		fclose(input_file);
		exit(1);
	    }

	    // Create and initialize the context
	    EVP_CIPHER_CTX *ctx;
	    if (!(ctx = EVP_CIPHER_CTX_new())) handleErrors("Function: MyAES_128_ECB_Decr: 1");
	    if (1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
		handleErrors("Function: MyAES_128_ECB_Decr");

	    // Buffer for reading file and for plaintext
	    unsigned char buffer[1024];
	    unsigned char plaintext[1024 + EVP_CIPHER_block_size(EVP_aes_128_ecb())];
	    int bytes_read, plaintext_len, len;

	    // Read from input file, decrypt, and write to output file
	    while ((bytes_read = fread(buffer, 1, sizeof(buffer), input_file)) > 0) {
		if (1 != EVP_DecryptUpdate(ctx, plaintext, &len, buffer, bytes_read))
		    handleErrors("Function: MyAES_128_ECB_Decr: 2");
		plaintext_len = len;
		if (fwrite(plaintext, 1, plaintext_len, output_file) != plaintext_len) {
		    perror("fwrite");
		    fclose(input_file);
		    fclose(output_file);
		    exit(1);
		}
	    }

	    // Finalize decryption
	    int errcode;
	    errcode = EVP_DecryptFinal_ex(ctx, plaintext, &len);
	    if (1 != errcode) {
	    	printf("Error Code = %d\n", errcode);
	    	handleErrors("Function: MyAES_128_ECB_Decr: 3");
	    }
	    plaintext_len = len;
	    if (fwrite(plaintext, 1, plaintext_len, output_file) != plaintext_len) {
		perror("fwrite");
		fclose(input_file);
		fclose(output_file);
		exit(1);
	    }

	    // Clean up
	    EVP_CIPHER_CTX_free(ctx);
	    fclose(output_file);

	    printf("File decrypted successfully and written to 'output.jpeg'\n");
}


