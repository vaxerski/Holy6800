
U8 main() {
    U8 addressLo = 0x00;
    U8 addressHi = 0x01;

    *addressHi = 'H';
    addressLo = addressLo + 1;
    *addressHi = 'E';
    addressLo = addressLo + 1;
    *addressHi = 'L';
    addressLo = addressLo + 1;
    *addressHi = 'L';
    addressLo = addressLo + 1;
    *addressHi = 'O';

    return 0;
}