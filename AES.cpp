/*
Broderick Holt
SJSU ID 009066109
CMPE 130 Section 2
AES.cpp

*/


#include "AES.h"
#include <iostream>
#include <string>
#include <cstring>

using namespace std;

AES::AES() {
}

void AES::SetKey(unsigned char* k) {
	for (int i = 0; i < 16; i++) {
		key[i] = k[i];
	}
}


void AES::EncryptPass(unsigned char* message, unsigned char* out) {
	unsigned char state[17] = "\0";
	for (int i = 0; i < 16; i++) {
		state[i] = message[i];
	}
	KeyExpansion();
	AddRoundKey(state, 0);
	for (int i = 1; i <= rounds; i++) {
		SubBytes(state);
		ShiftRows(state);
		MixColumns(state);
		AddRoundKey(state, i);
	}
	SubBytes(state);
	ShiftRows(state);
	AddRoundKey(state, 10);

	for (int i = 0; i < 16; i++) {
		out[i] = state[i];
	}
}

void AES::rotWord(unsigned char* wrd) {
	unsigned char tmp[5] = "\0";
	tmp[0] = wrd[1];
	tmp[1] = wrd[2];
	tmp[2] = wrd[3];
	tmp[3] = wrd[0];
	for (int i = 0; i < 4; i++) {
		wrd[i] = tmp[i];
	}

}

void AES::wordSubByte(unsigned char* wrd) {
	for (int i = 0; i < 4; i++) {
		wrd[i] = sbox[int(wrd[i])];
	}
}

void AES::roundConstant(unsigned char* wrd, int roundNum) {
	//XOR word with round constant
	unsigned char temp = '\0';
	temp = int(wrd[0]) ^ rcon[roundNum];
	wrd[0] = temp;
}

void AES::KeyExpansion() {
	/*
	Original cypherKey is 16 bytes = 128 bits
	Expanded key is 176 bytes = 1408 bits (original key times 11)
	*/
	//char expandedKey[bytes of key][# of round key, 0 is the original key]
	//char expandedKey[16][11]; //declared in AES.h

	//copy key into first 16 bytes of expanded key
	for (int i = 0; i < 16; i++) {
		expandedKey[i][0] = int(key[i]);
	}
	/*
	If we think of the expanded key as an array of 4 byte words,
	4*11=44 so we have 44 elements.
	the first 4 elements are the original cypher key, so only 40 expansions are needed.
	*/
	unsigned char tempWord[5] = "\0";
	//loop to generate the 10 round keys
	for (int i = 1; i < 11; i++) {
		for (int j = 0; j < 4; j++) {
			if (j == 0) {
				tempWord[0] = expandedKey[3][i - 1];
				tempWord[1] = expandedKey[7][i - 1];
				tempWord[2] = expandedKey[11][i - 1];
				tempWord[3] = expandedKey[15][i - 1];
			}
			else {
				tempWord[0] = expandedKey[j - 1][i];
				tempWord[1] = expandedKey[j - 1 + 4][i];
				tempWord[2] = expandedKey[j - 1 + 8][i];
				tempWord[3] = expandedKey[j - 1 + 12][i];
			}

			rotWord(tempWord);
			wordSubByte(tempWord);
			roundConstant(tempWord, i);

			expandedKey[j][i] = tempWord[0];
			expandedKey[j + 4][i] = tempWord[1];
			expandedKey[j + 8][i] = tempWord[2];
			expandedKey[j + 12][i] = tempWord[3];
		}

	}

}

void AES::AddRoundKey(unsigned char* state, int roundNum) {
	unsigned char temp[17] = "\0";
	for (int i = 0; i < 16; i++) {
		temp[i] = int(state[i]) ^ expandedKey[i][roundNum]; //bitwise XOR
	}
}

void AES::SubBytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = sbox[int(state[i])];
	}
}

void AES::ShiftRows(unsigned char* state) {
	unsigned char temp[17] = "\0";
	for (int i = 0; i < 16; i++) {
		temp[i] = state[i];
	}
	//shift 1
	state[4] = temp[5];
	state[5] = temp[6];
	state[6] = temp[7];
	state[7] = temp[4];
	//shift 2
	state[8] = temp[10];
	state[9] = temp[11];
	state[10] = temp[8];
	state[11] = temp[9];
	//shift 3
	state[12] = temp[15];
	state[13] = temp[12];
	state[14] = temp[13];
	state[15] = temp[14];
}

void AES::MixColumns(unsigned char* state) {
	
	unsigned char temp[17] = "\0";

	//Column1
	temp[0] = (MCMatrix[0] * int(state[0])) + (MCMatrix[1] * int(state[4])) + (MCMatrix[2] * int(state[8])) + (MCMatrix[3] * int(state[12]));
	temp[4] = (MCMatrix[4] * int(state[0])) + (MCMatrix[5] * int(state[4])) + (MCMatrix[6] * int(state[8])) + (MCMatrix[7] * int(state[12]));
	temp[8] = (MCMatrix[8] * int(state[0])) + (MCMatrix[9] * int(state[4])) + (MCMatrix[10] * int(state[8])) + (MCMatrix[11] * int(state[12]));
	temp[12] = (MCMatrix[12] * int(state[0])) + (MCMatrix[13] * int(state[4])) + (MCMatrix[14] * int(state[8])) + (MCMatrix[15] * int(state[12]));

	//Column2
	temp[1] = (MCMatrix[0] * int(state[1])) + (MCMatrix[1] * int(state[5])) + (MCMatrix[2] * int(state[9])) + (MCMatrix[3] * int(state[13]));
	temp[5] = (MCMatrix[4] * int(state[1])) + (MCMatrix[5] * int(state[5])) + (MCMatrix[6] * int(state[9])) + (MCMatrix[7] * int(state[13]));
	temp[9] = (MCMatrix[8] * int(state[1])) + (MCMatrix[9] * int(state[5])) + (MCMatrix[10] * int(state[9])) + (MCMatrix[11] * int(state[13]));
	temp[13] = (MCMatrix[12] * int(state[1])) + (MCMatrix[13] * int(state[5])) + (MCMatrix[14] * int(state[9])) + (MCMatrix[15] * int(state[13]));

	//Column3
	temp[2] = (MCMatrix[0] * int(state[2])) + (MCMatrix[1] * int(state[6])) + (MCMatrix[2] * int(state[10])) + (MCMatrix[3] * int(state[14]));
	temp[6] = (MCMatrix[4] * int(state[2])) + (MCMatrix[5] * int(state[6])) + (MCMatrix[6] * int(state[10])) + (MCMatrix[7] * int(state[14]));
	temp[10] = (MCMatrix[8] * int(state[2])) + (MCMatrix[9] * int(state[6])) + (MCMatrix[10] * int(state[10])) + (MCMatrix[11] * int(state[14]));
	temp[14] = (MCMatrix[12] * int(state[2])) + (MCMatrix[13] * int(state[6])) + (MCMatrix[14] * int(state[10])) + (MCMatrix[15] * int(state[14]));

	//Column4
	temp[3] = (MCMatrix[0] * int(state[3])) + (MCMatrix[1] * int(state[7])) + (MCMatrix[2] * int(state[11])) + (MCMatrix[3] * int(state[15]));
	temp[7] = (MCMatrix[4] * int(state[3])) + (MCMatrix[5] * int(state[7])) + (MCMatrix[6] * int(state[11])) + (MCMatrix[7] * int(state[15]));
	temp[11] = (MCMatrix[8] * int(state[3])) + (MCMatrix[9] * int(state[7])) + (MCMatrix[10] * int(state[11])) + (MCMatrix[11] * int(state[15]));
	temp[15] = (MCMatrix[12] * int(state[3])) + (MCMatrix[13] * int(state[7])) + (MCMatrix[14] * int(state[11])) + (MCMatrix[15] * int(state[15]));


	for (int i = 0; i < 16; i++) {
		state[i] = temp[i];
	}
	
}

void AES::DecryptPass(unsigned char* input, unsigned char* message) {
	unsigned char state[17] = "\0";
	for (int i = 0; i < 16; i++) {
		state[i] = input[i];
	}
	//KeyExpansion();
	AddRoundKey(state, 0);
	for (int i = 1; i <= rounds; i++) {
		invShiftRows(state);
		invSubBytes(state);
		invMixColumns(state);
		AddRoundKey(state, i);
	}
	invShiftRows(state);
	invSubBytes(state);
	AddRoundKey(state, 10);

	for (int i = 0; i < 16; i++) {
		message[i] = state[i];
	}
}

void AES::invShiftRows(unsigned char* state) {
	unsigned char temp[17] = "\0";
	for (int i = 0; i < 16; i++) {
		temp[i] = state[i];
	}
	//shift 1
	state[4] = temp[7];
	state[5] = temp[4];
	state[6] = temp[5];
	state[7] = temp[6];
	//shift 2
	state[8] = temp[10];
	state[9] = temp[11];
	state[10] = temp[8];
	state[11] = temp[9];
	//shift 3
	state[12] = temp[13];
	state[13] = temp[14];
	state[14] = temp[15];
	state[15] = temp[12];
}

void AES::invSubBytes(unsigned char* state) {
	for (int i = 0; i < 16; i++) {
		state[i] = invSBox[int(state[i])];
	}
}

void AES::invMixColumns(unsigned char* state) {
	unsigned char temp[17] = "\0";

	//Column1
	temp[0] = (invMCMatrix[0] * int(state[0])) + (invMCMatrix[1] * int(state[4])) + (invMCMatrix[2] * int(state[8])) + (invMCMatrix[3] * int(state[12]));
	temp[4] = (invMCMatrix[4] * int(state[0])) + (invMCMatrix[5] * int(state[4])) + (invMCMatrix[6] * int(state[8])) + (invMCMatrix[7] * int(state[12]));
	temp[8] = (invMCMatrix[8] * int(state[0])) + (invMCMatrix[9] * int(state[4])) + (invMCMatrix[10] * int(state[8])) + (invMCMatrix[11] * int(state[12]));
	temp[12] = (invMCMatrix[12] * int(state[0])) + (invMCMatrix[13] * int(state[4])) + (invMCMatrix[14] * int(state[8])) + (invMCMatrix[15] * int(state[12]));

	//Column2
	temp[1] = (invMCMatrix[0] * int(state[1])) + (invMCMatrix[1] * int(state[5])) + (invMCMatrix[2] * int(state[9])) + (invMCMatrix[3] * int(state[13]));
	temp[5] = (invMCMatrix[4] * int(state[1])) + (invMCMatrix[5] * int(state[5])) + (invMCMatrix[6] * int(state[9])) + (invMCMatrix[7] * int(state[13]));
	temp[9] = (invMCMatrix[8] * int(state[1])) + (invMCMatrix[9] * int(state[5])) + (invMCMatrix[10] * int(state[9])) + (invMCMatrix[11] * int(state[13]));
	temp[13] = (invMCMatrix[12] * int(state[1])) + (invMCMatrix[13] * int(state[5])) + (invMCMatrix[14] * int(state[9])) + (invMCMatrix[15] * int(state[13]));

	//Column3
	temp[2] = (invMCMatrix[0] * int(state[2])) + (invMCMatrix[1] * int(state[6])) + (invMCMatrix[2] * int(state[10])) + (invMCMatrix[3] * int(state[14]));
	temp[6] = (invMCMatrix[4] * int(state[2])) + (invMCMatrix[5] * int(state[6])) + (invMCMatrix[6] * int(state[10])) + (invMCMatrix[7] * int(state[14]));
	temp[10] = (invMCMatrix[8] * int(state[2])) + (invMCMatrix[9] * int(state[6])) + (invMCMatrix[10] * int(state[10])) + (invMCMatrix[11] * int(state[14]));
	temp[14] = (invMCMatrix[12] * int(state[2])) + (invMCMatrix[13] * int(state[6])) + (invMCMatrix[14] * int(state[10])) + (invMCMatrix[15] * int(state[14]));

	//Column4
	temp[3] = (invMCMatrix[0] * int(state[3])) + (invMCMatrix[1] * int(state[7])) + (invMCMatrix[2] * int(state[11])) + (invMCMatrix[3] * int(state[15]));
	temp[7] = (invMCMatrix[4] * int(state[3])) + (invMCMatrix[5] * int(state[7])) + (invMCMatrix[6] * int(state[11])) + (invMCMatrix[7] * int(state[15]));
	temp[11] = (invMCMatrix[8] * int(state[3])) + (invMCMatrix[9] * int(state[7])) + (invMCMatrix[10] * int(state[11])) + (invMCMatrix[11] * int(state[15]));
	temp[15] = (invMCMatrix[12] * int(state[3])) + (invMCMatrix[13] * int(state[7])) + (invMCMatrix[14] * int(state[11])) + (invMCMatrix[15] * int(state[15]));


	for (int i = 0; i < 16; i++) {
		state[i] = temp[i];
	}

}



