
U8 main() {
    U8 addressLo = 0;
    U8 addressHi = 0x02;
    // text accepted will be at 0x200
    // reading until an ascii NULL

    U8 foundWovels = 0;

    while (*addressHi != 0) {
        *addressHi = *addressHi & 223; // ~0x20, convert to uppercase

        if (*addressHi == 65 || *addressHi == 69 || *addressHi == 73 || *addressHi == 79 || *addressHi == 85) {
            foundWovels = foundWovels + 1;
        }

        if (addressLo == 255) {
            addressLo = 0;
            addressHi = addressHi + 1;
        } else {
            addressLo = addressLo + 1;
        }
    }

    return foundWovels; // done
}