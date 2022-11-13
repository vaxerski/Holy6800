
U8 main() {
    U8 addressLo = 0;
    U8 addressHi = 02;
    // text accepted will be at 0x200
    // reading until an ascii NULL

    if (*addressLo != 1) {
        return 1; // done
    }

    return 0; // done
}