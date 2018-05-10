/*
Broderick Holt
SJSU ID 009066109
CMPE 130 Section 2
Main Driver Program

*/

#include <iostream>
#include <string>
#include <cstring>
#include <cstdint>
#include <bitset>
#include "AES.h"


using namespace std;

int main() {

	
	unsigned char in[17] = "5reweodoj48dsleq"; 
		
	cout << in << endl;
	cout << endl;
	unsigned char out[17] = "\0";
	unsigned char message[17] = "\0";

	AES aesClass;

	aesClass.EncryptPass(in, out);
	cout << out << endl;
	/*
	for (int i = 0; i < 16; i++) {
		cout << hex << (int)out[i];
	}
	cout << endl;
	*/
	
	aesClass.DecryptPass(out, message);
	cout << message << endl;
	/*
	for (int i = 0; i < 16; i++) {
		cout << hex << (int)message[i];
	}
	cout << endl;
	*/
	
	cin.get();
	return 0;

}