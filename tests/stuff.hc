
U8 main() {
    U8 test = 0;

    while (1) {
        test += 1;

        if (test == 2) {
            continue;
        }

        if (test > 2) {
            break;
        }
    }

    return test; // done
}