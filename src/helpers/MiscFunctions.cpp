#include "MiscFunctions.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>

bool isNumber(const std::string& str, bool allowfloat) {
    std::string copy = str;
    if (*copy.begin() == '-')
        copy = copy.substr(1);

    if (copy.empty())
        return false;

    bool hex = false;
    if (copy[0] == '0' && copy[1] == 'x') {
        hex = true;
        copy = copy.substr(2);
    }

    bool point = !allowfloat;
    for (auto& c : copy) {
        if (c == '.') {
            if (point)
                return false;
            point = true;
            continue;
        }

        c = tolower(c);
        if (!std::isdigit(c) && (!hex || (c != 'a' && c != 'b' && c != 'c' && c != 'd' && c != 'e' && c != 'f')))
            return false;
    }

    return true;
}

std::string toHexFill(int num, int fill) {
    std::stringstream stream;
    stream << std::setfill('0') << std::setw(fill)
           << std::hex << num;
    std::string str = stream.str();
    std::transform(str.begin(), str.end(), str.begin(), ::toupper);

    return str;
};

int toInt(const std::string& str) {
    if (str.empty())
        return 0;

    if (str.length() < 2)
        return std::stoi(str);

    if (str[0] == '0' && str[1] == 'x')
        return std::stoi(str.substr(2), nullptr, 16);

    return std::stoi(str);
}