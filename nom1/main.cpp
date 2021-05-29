#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/sha.h>
#include <vector>
#include <iostream>
#include <string>
#include <fstream>
using namespace std;
int main ()
{

	CryptoPP::SHA256 hash;

	cout <<"Name: " << hash.AlgorithmName() << endl;
	cout << "Hash size:" << hash.DigestSize() << endl;
	cout << "Block size:" << hash.BlockSize() << endl;
	fstream file;
	string path = "/home/osboxes/Documents/pract_4/hash";
	string str_message, file_contents;
	file.open(path);
	while(true) {
		getline(file,str_message);
		if (file.fail())
			break;
		file_contents += str_message;
	}
	cout << "File: " << file_contents << endl;

	vector<byte> digest (hash.DigestSize());

	hash.Update(reinterpret_cast<const byte*>(file_contents.data()),file_contents.size());
	hash.Final(digest.data());

	cout << "HEX: ";
	CryptoPP::StringSource(digest.data(),digest.size(),true, new  CryptoPP::HexEncoder(new  CryptoPP::FileSink(cout)));
	cout << endl;
	return 0;
}
