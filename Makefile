all: merged

merged:
	@echo "Compiling the merged main program..."
	gcc -o aassIBE aassIBE.c  -lgmp -lpbc -lcrypto
	
runsetup:
	./aassIBE setup
	
runkeygen:
	./aassIBE keygen MSK.bin soumyadev@iiita.ac.in

runverifykey:
	./aassIBE verifykey ibeparams.bin private_key.bin soumyadev@iiita.ac.in

runencrypt:
	 ./aassIBE encrypt input.jpeg ibeparams.bin soumyadev@iiita.ac.in 

rundecrypt:
	 ./aassIBE decrypt ciphertext.bin encrypted_key.bin ibeparams.bin private_key.bin 
	
clean2:
	rm  MSK.bin ibeparams.bin private_key.bin ciphertext.bin encrypted_key.bin output.jpeg
	
clean:
	@echo "Remove all executable and output files..."
	rm aassIBE MSK.bin ibeparams.bin private_key.bin ciphertext.bin encrypted_key.bin output.jpeg
	

		
	

