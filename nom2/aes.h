#pragma once
#include <iostream>
#include <string>
#include <cstdlib>
#include <unistd.h>
#include <fstream>
#include <cryptopp/cryptlib.h>
#include <cryptopp/hex.h>
#include <cryptopp/files.h>
#include <cryptopp/pwdbased.h>
#include <cryptopp/filters.h>
#include <cryptopp/modes.h>
#include <cryptopp/osrng.h>
#include <cryptopp/sha.h>
#include <cryptopp/aes.h>

using namespace std;
using namespace CryptoPP;

class ACipher
{
private:
  string FIn;
  string FOut;
  string psw;

	string salt = "fgdflgkjtna";
public:
  ACipher() = delete;
  ACipher(const string& Input, const string& Output, const string& Pass);
  bool Encrypt ();
  bool Decrypt ();
};