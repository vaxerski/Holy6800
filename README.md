# Holy6800

A simple (not feature-complete) HolyC compiler for the Motorola 6800 released in 1974.

<br/>

## Language feature support
 - Types: `U8`, `I8`, `U0`, 16-bit pointers
 - Functions
 - Locals
 - `if`/`else` statements
 - `switch` statements
 - `while` loops
 - `continue`, `break` in switches & loops
 - Multi-argument expressions parsed with respect of the order of operations
 - Operators
 - Bytecode optimizer

## Running
See `holy6800 --help` for options.

## Notes
 - `else if` is NOT supported.
 - `()` in expressions are NOT supported (e.g. `2 * (2 - 2)`)
 - Not battle tested. Expect bugs.
 - `/` (div) is NOT supported.
 - The 6800 has an 8-bit data bus. Arithmetic on pointers may overflow. See `tests/manualPtrs.hc` for a solution if you want to do pointers manually.

## Calling convention
Holy6800 uses a `cdecl`-like calling convention.

Parameters are pushed and popped by the caller, in the order they appear in the function signature.

The function's return value is stored in `A`.

## Examples
See `tests/`.