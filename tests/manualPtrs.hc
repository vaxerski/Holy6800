U8 main() {
    U8 addressLo = 0x00;
    U8 addressHi = 0x02;

    *addressHi = 0xFF; // will write 0xFF to 0x0200

    return 1;
}