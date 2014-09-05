// Eric Grounds
// October 14, 2013

#include "AESEncryption.h"

using namespace std;

// Galois field
#define multiNum(x) ((x<<1) ^ (((x>>7) & 1) * 0x1b))

//////////////////////////////////////////////////////////
//                       Encrypt                        //
//                                                      //
//  This function begins the AES Encyption procedure,   //
//  which encrypts the plaintext using the              //
//  128-bit AES encryption algorithm (ECB mode).        //
//                                                      //
//  This function utilizes several other functions and  //
//  calls the main AES encrytion function, which        //
//  performs the actual encryption on each block of     //
//  data.                                               //
//                                                      //
//////////////////////////////////////////////////////////
void AES::Encrypt(string inKey, string inFile)
{
	outFileName = outFilePrefix + inFile;
    
	ReadFile(inFile);
    
	// Determine how many blocks the buffer will be split into
    length = buffer.length()/16.0;
    
    // Take the ceiling of that length to make sure we create enough blocks to hold all the characters
    numBlocks = ceil(length);
    
	// Store password inputed by user to be used as the 128-bit secret key in the encryption
    for(int i = 0; i < BLOCK_SIZE; i++) {
		key[i] =  inKey[i];
	}
    
    // Expand the keys
    KeyExpansion();
    
    // Create, encrypt, and write each block to output file
    for(int i = 0; i < numBlocks; i++) {
        // Copy 16 bytes from buffer to the current block of plainText
		memcpy(plainText, buffer.c_str(), 16);
        
        // If we are on the last block, and the block needs padding, use PCKS#5 standard to pad the block
		if (strlen((char*)plainText) < BLOCK_SIZE) {
			PadBlock();
		}
        
        // Remove those 16-bytes from the buffer to prevent re-encryption
		buffer.erase(0,16);
        
		// Encrypt the current blcok
		EncryptBlock();
        
		// Write current block to file
		WriteBlockToFile();
		
	}
    
	cout << "File " << inFile << " has been encrypted as " << outFileName << endl;
	cout << "Press <ENTER> to continue..." << endl;
}

/////////////////////////////////////////////////////////
//                    EncryptBlock                     //
//                                                     //
//  This is the main AES encryption                    //
//  function, which encrypts each block using          //
//  the 128-bit AES encryption algorithm (ECB mode).   //
//                                                     //
//  This function utilizes numerous other functions    //
//  to perform all the different steps of the AES      //
//  encryption algorithm.                              //
//                                                     //
//  The AES-128 encryption algorithm proceeds in 10    //
//  rounds.                                            //
//                                                     //
/////////////////////////////////////////////////////////
void AES::EncryptBlock()
{
	int currentRound = 0, i, j;
    
	// Put plaintext in state
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			state[j][i] = plainText[i*4 + j];
		}
	}
    
	// Add first round key
	AddRoundKey(currentRound);
	
	// First 9 rounds
	for(currentRound = 1; currentRound < ROUNDS; currentRound++) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(currentRound);
	}
    
	// Final round (Round 10)
	SubBytes();
	ShiftRows();
	AddRoundKey(currentRound);
    
	// Get ciphertext from the state matrix
	for(i = 0; i < 4; i++) {
		for(j = 0; j < 4; j++) {
			cipherText[i*4+j] = state[j][i];
		}
	}
}

///////////////////////////////////////////////////
//                  KeyExpansion                 //
//                                               //
//  This function creates the Key Scheduling     //
//  from the 128-bit secret key.                 //
//                                               //
///////////////////////////////////////////////////
void AES::KeyExpansion()
{
	unsigned char temp[4] = {0}, ch;
	int i, j;
	
	// The first round key
	for(i = 0; i < 4; i++) {
		roundKey[i*4] = key[i*4];
		roundKey[i*4+1] = key[i*4+1];
		roundKey[i*4+2] = key[i*4+2];
		roundKey[i*4+3] = key[i*4+3];
	}
    
	while (i < 44) {
		for(j = 0; j < 4; j++) {
			temp[j] = roundKey[(i-1) * 4 + j];
		}
        
		if (i % 4 == 0) {
            // RotWord - Performs a rotation on a 4 byte word
			ch = temp[0];
			temp[0] = temp[1];
			temp[1] = temp[2];
			temp[2] = temp[3];
			temp[3] = ch;

            // SubWord - Applies the S-box to each of the 4 bytes in a word
			temp[0] = SBOX[temp[0]];
			temp[1] = SBOX[temp[1]];
			temp[2] = SBOX[temp[2]];
			temp[3] = SBOX[temp[3]];
            
			temp[0] =  temp[0] ^ RCON[i/4];
		}
        
		roundKey[i*4+0] = roundKey[(i-4)*4+0] ^ temp[0];
		roundKey[i*4+1] = roundKey[(i-4)*4+1] ^ temp[1];
		roundKey[i*4+2] = roundKey[(i-4)*4+2] ^ temp[2];
		roundKey[i*4+3] = roundKey[(i-4)*4+3] ^ temp[3];
        
		i++;
	}
}

///////////////////////////////////////////////////
//                   AddRoundKey                 //
//                                               //
//  This function obtains the round key for      //
//  the current round from the Key Schedule.     //
//                                               //
///////////////////////////////////////////////////
void AES::AddRoundKey(int round)
{
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			state[j][i] ^= roundKey[round * 4 * 4 + i * 4 + j];
		}
	}
}

//////////////////////////////////////////////////
//                   SubBytes                   //
//                                              //
//  Substitutes each byte of the                //
//  state matrix by another                     //
//  byte through the S-box lookup table.        //
//                                              //
//////////////////////////////////////////////////
void AES::SubBytes()
{
	for(int i = 0; i < 4; i++) {
		for(int j = 0; j < 4; j++) {
			state[i][j] = SBOX[state[i][j]];
		}
	}
}

/////////////////////////////////////////////////////////
//                       ShiftRows                     //
//                                                     //
//  Performs a cyclical left shift                     //
//  on each row of the state matrix.                   //
//                                                     //
/////////////////////////////////////////////////////////
void AES::ShiftRows()
{
	unsigned char row;
    
	row = state[1][0];
	state[1][0] = state[1][1];
	state[1][1] = state[1][2];
	state[1][2] = state[1][3];
	state[1][3] = row;
    
	row = state[2][0];
	state[2][0] = state[2][2];
	state[2][2] = row;
    
	row = state[2][1];
	state[2][1] = state[2][3];
	state[2][3] = row;
    
	row = state[3][0];
	state[3][0] = state[3][3];
	state[3][3] = state[3][2];
	state[3][2] = state[3][1];
	state[3][1] = row;
}

///////////////////////////////////////////////////
//                  MixColumns                   //
//                                               //
//  Multiplies each column of the                //
//  state matrix with the 4x4 M matrix (below).  //
//                                               //
//                  [2 3 1 1]                    //
//                  [1 2 3 1]                    //
//                  [1 1 2 3]                    //
//                  [3 1 1 2]                    //
//                                               //
///////////////////////////////////////////////////
void AES::MixColumns()
{
	unsigned char firstCol, col, multiX;
    
	for(int i = 0; i < 4; i++) {
		firstCol = state[0][i];
        
		col = state[0][i] ^ state[1][i] ^ state[2][i] ^ state[3][i]; // ^ = XOR
        
		multiX = state[0][i] ^ state[1][i];
		multiX = multiNum(multiX);
		state[0][i] ^= multiX ^ col;
        
		multiX = state[1][i] ^ state[2][i];
		multiX = multiNum(multiX);
		state[1][i] ^= multiX ^ col;
        
		multiX = state[2][i] ^ state[3][i];
		multiX = multiNum(multiX);
		state[2][i] ^= multiX ^ col;
        
		multiX = state[3][i] ^ firstCol;
		multiX = multiNum(multiX);
		state[3][i] ^= multiX ^ col;
	}
}

////////////////////////////////////////////////
//                  ReadFile                  //
//                                            //
//  This function reads the data from the     //
//  plaintext file, specified by user.        //
//                                            //
////////////////////////////////////////////////
void AES::ReadFile(string fileName)
{
	inFileName = fileName;
	ifstream inFile;
	char ch; 
    
    // Open plaintext file to read data from
    inFile.open(fileName);
    
    // If opening of file failed, output error message
    if (!inFile) {
        cout << "Error, cannot open file " << fileName << endl;
		return;
    }
    
    // Otherwise, begin reading from plaintext file
    
    inFile.get(ch);    // Get first character from file
    
    // While file is readable, continue grabbing each character from file and store it in buffer
    while (inFile.good()) {
        buffer += ch;
        inFile.get(ch);
    }
    
    inFile.close();     // Close plaintext file
}

////////////////////////////////////////////////
//             WriteBlockToFile               //
//                                            //
//  This function writes one encrypted        //
//  block to the ciphertext file.             //
//                                            //
////////////////////////////////////////////////
void AES::WriteBlockToFile()
{
	ofstream outFile;
    
	// Open file to output to in append mode
    outFile.open(outFileName, ios::app);
    
    // If opening of output file failed, output error message
    if (outFile.fail()) {
		cout << "Error, cannot create " << outFileName << endl;
		return;
    }
    
	// Write encrypted block to output file
    for(int i = 0; i < 16; i++) {
        outFile << setw(4) << (int)cipherText[i];
    }
    outFile << endl;
    
    // Close the output file when done
    outFile.close();
}

////////////////////////////////////////////////
//                  PadBlock                  //
//                                            //
//  This function adds padding the the last   //
//  block, using the PKCS#5 standard.         //
//                                            //
////////////////////////////////////////////////
void AES::PadBlock()
{
	// Find value to be used in the padding
	int padValue = BLOCK_SIZE - strlen((char*)plainText);
    
	// Where in the block to begin adding the padding
    int padBegin = BLOCK_SIZE - padValue;
    
    // Pad the rest of the block using the padvalue
	for(int i = padBegin; i < BLOCK_SIZE; i++) {
		plainText[i] = padValue;
	}
}

