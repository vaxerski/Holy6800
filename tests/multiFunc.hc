U8 func(U8 value) {
    U8 var2 = 16 + value;

    return var2;
}

U8 main() {
    U8 var = 16 + func(16);

    return var;
}