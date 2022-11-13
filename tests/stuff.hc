
U8 main() {
    U8 addressLo = 0;
    U8 addressHi = 02;
    // text accepted will be at 0x200
    // reading until an ascii NULL

    while (*addressHi != 0) {
        *addressHi = *addressHi & 223; // ~0x20, convert to uppercase

        if (addressLo == 255) {
            addressLo = 0;
            addressHi = addressHi + 1;
        } else {
            addressLo = addressLo + 1;
        }
    }

    return 0; // done
}