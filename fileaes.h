#pragma once

#include <string>
#include <cstdint>

using namespace std;
string crypt(string textin, string keyin, uint8_t CTR[16]);