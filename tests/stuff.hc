
U8 main() {
    U8 addressA = 0;
    U8 addressB = 01;

    U8 counter = 255 & 4;

    *addressB = counter;

    return 0;
}