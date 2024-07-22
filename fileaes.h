#pragma once

#include <string>
#include <cstdint>
#include <algorithm>
#include <cstring>
#include <cctype> // for isspace

using namespace std;
string crypt(string textin, string keyin, uint8_t CTR[16]);
string bintohex(const string &bin);
string hextobin(const string &hex);