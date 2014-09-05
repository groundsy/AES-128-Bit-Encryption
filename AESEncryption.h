// Eric Grounds
// October 14, 2013

#ifndef AES_ENCRYPTION_H
#define AES_ENCRYPTION_H

#include <stdio.h>
#include <iostream>
#include <iomanip>
#include <math.h>
#include <fstream>
#include <string>
#include "AESConstants.h"

using namespace std;

class AES {
	private:
		static const int BLOCK_SIZE = 16;
		static const int ROUNDS = 10;
		unsigned char plainText[BLOCK_SIZE];
		unsigned char cipherText[BLOCK_SIZE];
		unsigned char key[BLOCK_SIZE];
		unsigned char roundKey[240];
		unsigned char state[4][4];
		int numBlocks;
		float length;
		string buffer;
		string outFileName;
		string outFilePrefix;
		string inFileName;
    
		void KeyExpansion();
		void AddRoundKey(int round);
		void SubBytes();
		void ShiftRows();
		void MixColumns();
		void EncryptBlock();
		void PadBlock();
		void ReadFile(string fileName);
		void WriteBlockToFile();
    
	public:
	    void Encrypt(string inKey, string inFile);
    
	    AES::AES() {
			numBlocks = 0;
			length = 0;
			buffer = "";
			outFileName = "";
			outFilePrefix = "cipher_";
			inFileName = "";
        
	        for (int i = 0; i < BLOCK_SIZE; i++) {
				plainText[i] = NULL;
				cipherText[i] = NULL;
				key[i] = NULL;
			}
        
	        for (int i = 0; i < 240; i++) {
		        roundKey[i] = NULL;
	        }
			for (int i = 0; i < 4; i++) {
	            for (int j = 0; j < 4; j++) {
					state[i][j] = NULL;
				}
			}
		}
};

#endif