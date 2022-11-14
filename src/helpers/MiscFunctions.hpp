#pragma once
#include <string>

bool isNumber(const std::string& str, bool allowfloat = false);
std::string toHexFill(int num, int len);
int toInt(const std::string& str);