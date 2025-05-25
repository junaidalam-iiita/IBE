

#include "AASS_IBE_header.h"

void IBE_Setup_main();
void IBE_Keygen_main(int argc, char **argv);
void IBE_Encrypt_main(int argc, char **argv);
void IBE_Decrypt_main(int argc, char **argv);
void IBE_Verifykey_main(int argc, char **argv);

int main(int argc, char **argv) {
	
	if (strcmp(argv[1], "setup") == 0){
		IBE_Setup_main();
	}
	else if (strcmp(argv[1], "keygen") == 0){
		IBE_Keygen_main( argc, (argv+1) );
	}
	else if (strcmp(argv[1], "encrypt") == 0){
		IBE_Encrypt_main( argc, (argv+1) );
	}
	else if (strcmp(argv[1], "decrypt") == 0){
		IBE_Decrypt_main( argc, (argv+1) );
	}
	else if (strcmp(argv[1], "verifykey") == 0){
		IBE_Verifykey_main( argc, (argv+1) );
	}
	else{
		printf("Incorrect Command\n");
	}

	
	return 0;
}

void IBE_Setup_main() {
    // Variable Declarations
    FILE *msk_file, *ibparams_file;
    SETUPVALS setup_vals;
    
    // Initialize the PBC libraray global parameters
    myPBC_Initialize();
    
    // Create and Open Two Output files 'MSK.bin' and 'ibeparams.bin'
    msk_file = fopen("MSK.bin", "wb");
    if(msk_file == NULL){
    	printf("Error: Couldn't create MSK output file!\n");
    	exit(1);
    }
    
    ibparams_file = fopen("ibeparams.bin", "wb");
    if(ibparams_file == NULL){
    	printf("Error: Couldn't create ibeparams output file!\n");
    	exit(1);
    }
    
    // Call the 'setup' function to generate the setup phase outputs of IBE, viz., MSK and the ibeparams g and g1
    setup_vals = ibe_setup();
    
    // Save the MSK (alpha) in 'MSK.bin' file  and save the ibeparams g and g1 in 'ibeparams.bin' file
    save_element_to_file(setup_vals.alpha, msk_file);
    save_element_to_file(setup_vals.ibeparams.g, ibparams_file);
    save_element_to_file(setup_vals.ibeparams.g1, ibparams_file);
    
    // Close and Clear Everything
    fclose(msk_file);
    fclose(ibparams_file);
    element_clear(setup_vals.alpha);
    element_clear(setup_vals.ibeparams.g);
    element_clear(setup_vals.ibeparams.g1);
    pairing_clear(global_params);
    printf("Setup Executed Successfully. \nThe generated MSK saved in 'MSK.bin', IBE-Parameters saved in 'ibeparams.bin'.\n");
}

void IBE_Keygen_main(int argc, char **argv) {
	// Variable Declarations
	FILE * msk_file, * privt_key_file;
	char * ID;
	element_t alpha, private_key;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
    	
    	// Initialize all PBC element variables
    	element_init_Zr(alpha, global_params);
    	element_init_G1(private_key, global_params);
    	
	// Checks whther minimum 2 command line arguments have been given or not
	if(argc < 3){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the Input file containing the MSK & also Read the ID specified as command-line arguments
	msk_file = fopen(argv[1], "rb");
	if(msk_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[1]);
    		exit(1);
    	}
    	
	ID = argv[2];
	
	// Create and Open an Output file 'private_key.bin'
	privt_key_file = fopen("private_key.bin", "wb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't create output file for Private_Key: \n");
    		exit(1);
    	}
    	
    	// Read the MSK (alpha) from the given input file
    	read_element_from_file(alpha, msk_file);
    	
    	// Call the 'Keygen()' function to generate the Private-Key from the given MSK and ID
    	ibe_keygen(private_key, alpha, ID);

	// Save the Private-Key in the 'private_key.bin' file 
    	save_element_to_file(private_key, privt_key_file);
    	
    	// Close and Clear Everything
    	fclose(msk_file);
    	fclose(privt_key_file);
    	element_clear(alpha);
    	element_clear(private_key);
    	pairing_clear(global_params);
    	printf("Keygen Executed Successfully. \nThe generated Pivate-Key is saved in 'private_key.bin'.\n");
}

void IBE_Encrypt_main(int argc, char **argv) {
	// Variable Declarations
	FILE * plaintext_file, * params_file; 
	unsigned char * ID;
	unsigned char symkey[EVP_MAX_KEY_LENGTH];
	IBEPARAMS ibeparams;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
    	
    	// Initialize all PBC element variables
    	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
	// Checks whether minimum 3 command line arguments have been given or not
	if(argc < 4){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the two Input files containing the Plaintext data, and containing the IBE-Params,  & also Read the ID specified as command-line arguments
	plaintext_file = fopen(argv[1], "rb");
	if(plaintext_file == NULL){
    		printf("Error: Couldn't open spefified input data-file: %s\n", argv[1]);
    		exit(1);
    	}
    	
    	params_file = fopen(argv[2], "rb");
	if(params_file == NULL){
    		printf("Error: Couldn't open spefified input params-file: %s\n", argv[2]);
    		exit(1);
    	}

	ID = argv[3];
	
    	// Read the IBE-Params from the specified input file
	read_element_from_file(ibeparams.g, params_file);
    	read_element_from_file(ibeparams.g1, params_file);
    	
    	// Generate a Random AES symmetric-key
    	if (!RAND_bytes(symkey, EVP_MAX_KEY_LENGTH)) 
    	 	handleErrors("Function: ibe-encrypt.c main");
	
	// Encrypt the data-file with the symmetric-key --- output will be stored in 'ciphertext.bin'
	MyAES_128_ECB_Encr(plaintext_file, symkey);
	
	// Encrypt the symmetric-key under the given ID and params --- output will be stored in 'encrypted_key.bin'
	ibe_encrypt(symkey, ID, ibeparams);
	
	// Close and Clear Everything
	fclose(plaintext_file);
	fclose(params_file);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
}

void IBE_Decrypt_main(int argc, char **argv) {
	// Variable declarations
	FILE *cipher_file, *encrptd_key_file, *ibparams_file, *privt_key_file;
	element_t private_key, C1;
   	IBEPARAMS ibeparams;
   	unsigned char * C2, * decr_key;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
	
	// Intializing all PBC 'element_t' element variables
    	element_init_G1(private_key, global_params);
    	element_init_G2(C1, global_params);
	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
    	// All dynamic memory allocations
    	decr_key = malloc(EVP_MAX_KEY_LENGTH);
    	C2 = malloc(EVP_MAX_KEY_LENGTH);
    	
    	// Checks whether minimum 4 command line arguments have been given or not
	if(argc < 5){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the four Input files containing the Ciphertext-data, encrypted-symmetric-key, IBE-Params and the IBE Private-Key
	cipher_file = fopen(argv[1], "rb");
	if(cipher_file == NULL){
    		printf("Error: Couldn't open Specified Ciphertext File %s \n", argv[1]);
    		exit(1);
    	}
    	
    	encrptd_key_file = fopen(argv[2], "rb");
	if(encrptd_key_file == NULL){
    		printf("Error: Couldn't open Specified Encrypted-Key File %s \n", argv[2]);
    		exit(1);
    	}
    	
    	ibparams_file = fopen(argv[3], "rb");
	if(ibparams_file == NULL){
    		printf("Error: Couldn't open Specified IBE-Params File %s \n", argv[3]);
    		exit(1);
    	}
    	
    	privt_key_file = fopen(argv[4], "rb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't open Specified IBE-Priate-Ky File %s \n", argv[4]);
    		exit(1);
    	}
    	
    	// Read the IBE Private-key from file
    	read_element_from_file(private_key, privt_key_file);
    	
    	// Read the IBE Params from file
    	read_element_from_file(ibeparams.g, ibparams_file);
    	read_element_from_file(ibeparams.g1, ibparams_file);
    	
    	// Read the IBE Ciphertext(C1,C2) from file
    	read_element_from_file(C1, encrptd_key_file);
    	int retcode = fread(C2, 1, EVP_MAX_KEY_LENGTH, encrptd_key_file);
    	if(retcode == 0){
    		printf("Error while reading from encrptd_key_file!\n");
    		exit(1);
    	}
    	   	
    	// Deccrypt the IBE-Ciphertext(C1,C2) to get the symmetric key
    	ibe_decrypt(private_key, C1, C2, ibeparams, decr_key);
    	
    	// Use the symmetric key to decrypt the ciphertext data-file   -- output will be saved into 'output.jpeg'
	MyAES_128_ECB_Decr(cipher_file, decr_key);
	
	// Close and Clear Everything
	fclose(cipher_file);
	fclose(encrptd_key_file);
	fclose(ibparams_file);
	fclose(privt_key_file);
	element_clear(private_key);
	element_clear(C1);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
	free(decr_key);
	free(C2);
}

void IBE_Verifykey_main(int argc, char **argv) {
	// Variable Declarations
	FILE * ibparams_file, * privt_key_file;
	char * ID;
	element_t private_key;
	IBEPARAMS ibeparams;
	
	// Initialize the PBC libraray global parameters
    	myPBC_Initialize();
	
	// Initialize all PBC element variables
	element_init_G1(private_key, global_params);
    	element_init_G2(ibeparams.g, global_params);
    	element_init_G2(ibeparams.g1, global_params);
    	
	// Checks whther minimum 3 command line arguments have been given or not
	if(argc < 4){
		printf("Error: Please Enter Correct Execution Command %d !!!\n", argc);
		exit(1);
	}
	
	// Open the Input files containing the IBE-Params and the Private-Key, & also Read the ID specified as command-line arguments
	ibparams_file = fopen(argv[1], "rb");
	if(ibparams_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[1]);
    		exit(1);
    	}
	
	privt_key_file = fopen(argv[2], "rb");
	if(privt_key_file == NULL){
    		printf("Error: Couldn't open spefified input file: %s\n", argv[2]);
    		exit(1);
    	}
    	
	ID = argv[3];
    	
    	// Read the Private-Key and the IBE-Params from the specified input files
    	read_element_from_file(private_key, privt_key_file);
    	read_element_from_file(ibeparams.g, ibparams_file);
    	read_element_from_file(ibeparams.g1, ibparams_file);
    	
    	// Call our Verifykey() function to chcek whether the Private-Key matches with the given ID, under the given IBE-params or not
	if( ibe_verify_key(private_key, ID, ibeparams)){
		printf("Private-key Matches with the Given ID against the Given IBE Params. \n");
	}
	else{
		printf("!!! Private-key Does-Not with the Given ID against the Given IBE Params.!!! \n");
	}
	
	// Close and Clear Everything
	fclose(ibparams_file);
	fclose(privt_key_file);
	element_clear(private_key);
	element_clear(ibeparams.g);
	element_clear(ibeparams.g1);
	pairing_clear(global_params);
}

