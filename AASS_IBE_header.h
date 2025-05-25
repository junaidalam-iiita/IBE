/* This Header File Contains The Implementataions of All Algorithms related to IBE. There are total 7 Functions. Two hash functions, viz., H1 and H2, Four main algo.s of IBE, viz., 1) ibe_setup, 2) ibe_keygen, 4) ibe_encrypt and 5) ibe_decrypt. Additionally, we also have a 'ibe_verify_key' algo.,
Decsription of each of these functions are given below. */

#include "AASS_PBC_utils.h"

// IBE Paramaters Definations

#define IBE_MSG_STR_LEN     EVP_MAX_KEY_LENGTH 
/* Here, we are defining our IBE message length (which is usually deonted as 'n' in literature). 
						Since, in this implementaion, we are essentailly encrypting a symmetric-key, we set the message length as 'EVP_MAX_KEY_LENGTH'
						which is the maximum key length supported by the openSSL EVP (Enveloping) interface for symmetric ciphers. */ 

// Defination of necessary data-structures.

typedef struct {
    element_t g;
    element_t g1;
} IBEPARAMS;

typedef struct {
    element_t alpha;
    IBEPARAMS ibeparams;
} SETUPVALS;


/**** Prototype of the Functions ***/

void H1(element_t Q, char * str);
/* Hash Function H1: {0,1}^* --> G1 .
Maps an input string(str) of any arbitrary length to an element in G1 ('Q'). 
Note: The input string must be a character-string (i.e., a null-terminated ('\0') character string) */

void H2(unsigned char * ssnkey, element_t X);
/* Hash Function H2: GT --> {0,1}^n .
Maps an element of GT to a randomized string of n bytes length. [NOTE: n-bytes , not bits] 
where n is the IBE-Message-Size */

SETUPVALS ibe_setup(); 
/* Setup Algo:
When invoked, this function generates MSK (alpha) and IBE-Parameters 'g' and 'g1'.
Note: g1=g^{alpha} [in some literature also denoted as 'P' and 'P_{pub}']
All the generated values are packed inside a struct of type SETUPVALS (defined above) and returned */

void ibe_keygen(element_t private_key, element_t alpha, char *ID);
/* Keygen Algo:
This function generates the IBE Private-Key from a given identity-string (ID) and  a given MSK value (alpha).
The generated Private-Key is passed back inside the argumet 'private_key' */

void ibe_encrypt(unsigned char * msg, char * ID, IBEPARAMS ibeparams);
/* IBE Encyption Algo:
 Encrypts the given message 'msg' under the given ID and given ibe-params. 
 Note: In IBE-Encryption, usually a symmetric-key is given as the input message-string (msgstr) - which is an array of random bytes.
 The output (ciphertext) is saved into an output file named 'encrypted_key.bin'.
 Note2: The length of the message must be 'EVP_MAX_KEY_LENGTH'
 */

void ibe_decrypt(element_t D, element_t C1, unsigned char * C2, IBEPARAMS ibeparams, unsigned char * decrypted);
/* IBE Decryption Algo:
Decrypts the given IBE-ciphertext(C1, C2) under the given ibe-params using the given Priivate-Key (D), and returns back the decrypted result in 'decrypted' .
Note: In IBE-Decryption, usually the given ciphertext is an encrypted symmetric-key. */

int ibe_verify_key(element_t private_key, char *ID, IBEPARAMS ibeparams);
/* Private-Key Verification Algo:
This function takes an IBE Private-Key, an identity-string (ID) and the ibe-params, and checks whether  the given Private-Key is Correct against the given ID or not.
It returns 1 on success, 0 otherwise. */

	//////////////////////////////////////////////////////////////////////////////////////////////////////////

/*            **********    Implementations of the 'ibe_header.h' Functions  *****          */

/* IMPLEMENTATION of H1()  */

void H1(element_t Q, char * str){
	element_from_hash(Q, str, strlen(str));
}

/* IMPLEMENTATION of H2()  */

void H2(unsigned char * ssnkey, element_t X){
	// First, conver the given PBC element into binary string
	int len = element_length_in_bytes(X);
 	unsigned char * hashed = pbc_malloc(len);
 	element_to_bytes(hashed, X);
 	
 	// Then, expand the string as per the required length
 	H0(ssnkey, IBE_MSG_STR_LEN, hashed, len);
 	pbc_free(hashed);
}

/* IMPLEMENTATION of ibe_setup()  */

SETUPVALS ibe_setup() {
    //printf("SETUP ALGO INVOKED...\n\n");
    SETUPVALS setup_vals;
    
    element_init_G2(setup_vals.ibeparams.g, global_params);
    element_init_G2(setup_vals.ibeparams.g1, global_params);
    element_init_Zr(setup_vals.alpha, global_params);
    
    // Take 'g' and 'alpha' random
    element_random(setup_vals.ibeparams.g);
    element_random(setup_vals.alpha);
    
    //Then, calculate g1 = g^{alpha}
    element_pow_zn(setup_vals.ibeparams.g1, setup_vals.ibeparams.g, setup_vals.alpha);
    
    return setup_vals;
}

/* IMPLEMENTATION of ibe_keygen()  */

void ibe_keygen(element_t D, element_t alpha, char *ID) {
    //printf("KEYGEN ALGO INVOKED...\n\n");
    element_t Q;  
    element_init_G1(Q, global_params);
    
    // Calculate: Q = H1(ID)
    H1(Q, ID);

    // Calcualte: D = Q^{alpha}
    element_pow_zn(D, Q, alpha);
    
    element_clear(Q);
}

/* IMPLEMENTATION of ibe_encrypt()  */

void ibe_encrypt(unsigned char * msg, char * ID, IBEPARAMS ibeparams){
	//printf("IBE-Encryption ALGO INVOKED...\n\n");
	FILE * key_file = fopen("encrypted_key.bin", "wb");
	if(key_file == NULL){
    		printf("Error: Couldn't Create output file for storing the encrypted-Key\n");
    		exit(1);
    	}
	unsigned char *ssnkey, *C2;
	element_t Q, r, C1, K1, temp;  
	
	ssnkey = malloc(IBE_MSG_STR_LEN);
 	C2 = malloc(IBE_MSG_STR_LEN);
 	
    	element_init_G1(Q, global_params);
    	element_init_G2(C1, global_params);
    	element_init_GT(temp, global_params);
  	element_init_GT(K1, global_params);
    	element_init_Zr(r, global_params);
    	
    	// Calcuation of C1 = g^r and K1 = e(H1(ID), g1)^r, where r is a random no.
    	H1(Q, ID);
    	element_random(r);
    	element_pow_zn(C1, ibeparams.g, r);
    	element_pairing(temp, Q, ibeparams.g1);
 	element_pow_zn(K1, temp, r);
 	
 	// Calculate ssnkey = H2(K1) = H2( e(H1(ID), g1)^r )
	  
 	H2(ssnkey, K1);
	
 	// Calculate C2 = message XOR ssnkey = message XOR H2(K1) = message XOR H2( e(H1(ID), g1)^r )
    	xor_bytes(C2, msg, ssnkey, IBE_MSG_STR_LEN);
    	
    	// Saving Ciphertext (C1, C2) into file
    	  
    	save_element_to_file(C1, key_file);
    	size_t retcode = fwrite(C2, 1, IBE_MSG_STR_LEN, key_file);
    	if(retcode == 0){
    		printf("Error while saving encrypted-key into the file!\n");
    		exit(1);
    	}
  	
    	//printf("The IBE-Encryption Encrypted successfully and output written to 'encrypted_key.bin' \n");
    	
    	element_clear(Q);
    	element_clear(r);
    	element_clear(C1);
    	element_clear(K1);
    	element_clear(temp);
    	free(ssnkey);
    	free(C2);
    	fclose(key_file);
    	printf("IBE Encryption Executed Successfully, and the output is saved into 'encrypted_key.bin'.\n ");
}

/* IMPLEMENTATION of ibe_decrypt()  */

void ibe_decrypt(element_t D, element_t C1, unsigned char * C2, IBEPARAMS ibeparams, unsigned char * decrypted){
	element_t K2;
	unsigned char *ssnkey;
  	
  	ssnkey = malloc(IBE_MSG_STR_LEN);
  	
  	element_init_GT(K2, global_params);
  	
  	// Calculate K2 = e(D, C1)
  	element_pairing(K2, D, C1);
  	
  	// Calculate ssnkey = H2(K2) = H2( e(D, C1) )
  	H2(ssnkey, K2);
  	
  	// Calculate decrypted = C2 XOR ssnkey = C2 XOR H2( e(D, C1) )
  	xor_bytes(decrypted, C2, ssnkey, IBE_MSG_STR_LEN);
  	
  	element_clear(K2);
  	free(ssnkey);
}

/* IMPLEMENTATION of ibe_verify_key()  */

int ibe_verify_key(element_t D, char *ID, IBEPARAMS ibeparams){
	//printf("Private-Key Verify ALGO INVOKED...\n\n");
	int r = 0;
	element_t Q, temp1, temp2;  
    	element_init_G1(Q, global_params);
    	element_init_GT(temp1, global_params);
    	element_init_GT(temp2, global_params);
    	
    	// Just check whether e(D,g) == e( H1(ID), g1 ) or not 
	H1(Q, ID);
    	element_pairing(temp1, D, ibeparams.g);
    	element_pairing(temp2, Q, ibeparams.g1);
    	if (!element_cmp(temp1, temp2)) r = 1;
 
    	element_clear(Q);
    	element_clear(temp1);
    	element_clear(temp2);
	return r;
}

							/*  THE END  */
