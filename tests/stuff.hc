
U8 main() {
    U8* address = 0x0100;

    *address = 'H';
    address = address + 1;
    *address = 'E';

    U8 addressLo = 0x02;
    U8 addressHi = 0x01;

    *addressHi = 'L';

    return 0;
}