
U8 main() {
    U8* address = 0x0200;
    U8 foundWovels = 0;

    while (*address != 0) {
        *address = *address & ~0x20; // convert to uppercase

        if (*address == 65 || *address == 69 || *address == 73 || *address == 79 || *address == 85) {
            foundWovels += 1;
        }

        address += 1;
    }

    return foundWovels; // done
}