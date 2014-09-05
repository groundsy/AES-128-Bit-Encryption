// Eric Grounds
// October 14, 2013

#include <iostream>
#include <string>
#include <fstream>
#include "AESEncryption.h"

using namespace std;


int main()
{
    string inKey, inFileName;
	ifstream inFile;
    AES newCipher;

	// Get text file name from user
	do {
		cout << "Enter the plaintext file: ";
		getline(cin, inFileName);
		inFile.open(inFileName);
	} while (!inFile.good());

	inFile.close();
	
	// Get password from user
	do {
		cout << "Enter a 16-character password : ";
		getline(cin, inKey);
	} while(inKey.length() < 16);
    
	 // Open output file
    ofstream outFile("cipher_"+inFileName);
	
     // Clear contents, since file will be opened in append mode
    outFile.clear();

     // Close file
    outFile.close();

    newCipher.Encrypt(inKey,inFileName);
    
    cin.get();
    
    return 0;
}
