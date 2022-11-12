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

    bool point = !allowfloat;
    for (auto& c : copy) {
        if (c == '.') {
            if (point)
                return false;
            point = true;
            continue;
        }

        if (!std::isdigit(c))
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