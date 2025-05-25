#!/bin/sh
echo "Executing Script-1..."
make clean2
./aassIBE setup
./aassIBE keygen MSK.bin soumyadev@iiita.ac.in
./aassIBE encrypt input.jpeg ibeparams.bin soumyadev@iiita.ac.in
./aassIBE decrypt ciphertext.bin encrypted_key.bin ibeparams.bin private_key.bin
./aassIBE verifykey ibeparams.bin private_key.bin soumyadev@iiita.ac.in
