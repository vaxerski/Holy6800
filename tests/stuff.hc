
U8 test(U8 hi) {
    U8 hi2 = hi;
    return hi2;
}

U8 main() {
    U8* address = 0x0200;
    U8 foundWovels = 0;

    test(2);

    while (*address != 0) {
        *address = *address & ~0x20; // convert to uppercase

        switch (*address) {
            case 65:
            case 69:
            case 73:
            case 79:
            case 85: {
                foundWovels += 1;
            }
        }

        address += 1;
    }

    return foundWovels; // done
}