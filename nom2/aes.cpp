#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include "aes.h"

ACipher::ACipher(const string& Input, const string& Output, const string& Pass)
{
	FIn = Input;
	FOut = Output;
	psw = Pass;
}

bool ACipher::Encrypt ()
{
	SecByteBlock key(32);
	PKCS12_PBKDF<SHA512> pbkdf;
	pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

	cout << "Key: ";
	StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

	AutoSeededRandomPool prng;
	byte iv[AES::BLOCKSIZE];
	prng.GenerateBlock(iv, sizeof(iv));

	ofstream pull(string(FOut + ".iv").c_str(), ios::out | ios::binary);
	pull.write((char*)iv, AES::BLOCKSIZE);
	pull.close();

	cout << "IV Successfully created: " << FOut << ".iv" << endl;

	try {
		CBC_Mode<AES>::Encryption encr;
		encr.SetKeyWithIV(key, key.size(), iv);

		FileSource fs(FIn.c_str(), true, new StreamTransformationFilter(encr, new FileSink(FOut.c_str())));
	}

	catch (const Exception& e) {
		cerr << e.what() << endl;

		return false;
	}

	return true;
}

bool ACipher::Decrypt ()
{
	SecByteBlock key(32);
	PKCS12_PBKDF<SHA512> pbkdf;
	pbkdf.DeriveKey(key.data(), key.size(), 0, (byte*)psw.data(), psw.size(), (byte*)salt.data(), salt.size(), 1024, 0.0f);

	cout << "Key: ";
	StringSource(key.data(), key.size(), true, new HexEncoder( new FileSink(cout) ));

	cout << endl;

	byte iv[AES::BLOCKSIZE];
	ifstream pool(string(FIn + ".iv").c_str(), ios::in | ios::binary);

	if (pool.good()) {
		pool.read((char*)&iv, AES::BLOCKSIZE);
		pool.close();
	}

	else if (pool.bad()) {
		cerr << "IV file not found!" << endl;
		pool.close();
		return false;
	}

	else {
		cerr << "Incorrect IV file!" << endl;
		pool.close();
		return false;
	}

	try {
		CBC_Mode<AES>::Decryption decr;
		decr.SetKeyWithIV(key, key.size(), iv);

		FileSource fs(FIn.c_str(), true, new StreamTransformationFilter(decr, new FileSink(FOut.c_str())));
	}

	catch (const Exception& e) {
		cerr << e.what() << endl;

		return false;
	}

	return true;
}
