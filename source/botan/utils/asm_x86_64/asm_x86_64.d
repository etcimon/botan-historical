/*
* Assembly Macros for 64-bit x86
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.asm_x86_64.asm_x86_64;
/*
* General/Global Macros
*/

enum ALIGN = "align 16";

/*
* Conditional Jumps
*/
string JUMP_IF_ZERO(string REG, string LABEL)() {
    return `cmp ` ~ REG ~ `, ` ~ IMM(0) ~ `;
            jz ` ~ LABEL ~ `;`;
}

string JUMP_IF_LT(string REG, int NUM, string LABEL) {
    return `cmp ` ~ IMM(NUM) ~ `, ` ~ REG ~ `;
            jl ` ~ LABEL ~ `;`;
}

/*
* Register Names
*/
enum R0 = "RAX";
enum R1 = "RBX";
enum R2 = "RCX";
enum R2_32 = "ECX";
enum R3 = "RDX";
enum R3_32 = "EDX";
enum R4 = "RSP";
enum R5 = "RBP";
enum R6 = "RSI";
enum R6_32 = "ESI";
enum R7 = "RDI";
enum R8 = "R8";
enum R9 = "R9";
enum R9_32 = "R9D";
enum R10 = "R10";
enum R11 = "R11;";
enum R12 = "R12";
enum R13 = "R13";
enum R14 = "R14";
enum R15 = "R15";
enum R16 = "R16";

enum ARG_1 = R7;
enum ARG_2 = R6;
enum ARG_2_32 = R6_32;
enum ARG_3 = R3;
enum ARG_3_32 = R3_32;
enum ARG_4 = R2;
enum ARG_4_32 = R2_32;
enum ARG_5 = R8;
enum ARG_6 = R9;
enum ARG_6_32 = R9_32;

enum TEMP_1 = R10;
enum TEMP_2 = R11;
enum TEMP_3 = ARG_6;
enum TEMP_4 = ARG_5;
enum TEMP_5 = ARG_4;
enum TEMP_5_32 = ARG_4_32;
enum TEMP_6 = ARG_3;
enum TEMP_7 = ARG_2;
enum TEMP_8 = ARG_1;
enum TEMP_9 = R0;

/*
* Memory Access Operations
*/
string ARRAY4(string REG, int NUM) { return `[` ~ REG ~ ` + 4*` ~ NUM ~ `]`; }
string ARRAY8(string REG, int NUM) { return `[` ~ REG ~ ` + 8*` ~ NUM ~ `]`; }
string ASSIGN(string TO, string FROM) { return `mov ` ~ TO ~ `, ` ~ FROM ~ `;`; }


/*
* ALU Operations
*/
string IMM(int VAL) { return VAL.to!string; }

string ADD(string TO, string FROM) { return `add ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string ADD_IMM(string TO, int NUM) { return ADD(TO, IMM(NUM)); }
string ADD_LAST_CARRY(string REG) { return `adc ` ~ REG ~ `, ` ~ IMM(0) ~ `;`; }
string ADD_W_CARRY(string TO1, string TO2, string FROM) { return `add ` ~ TO1 ~ `, ` ~ FROM ~ `;
                                                                    adc ` ~ TO2 ~ `, ` ~ IMM(0) ~ `;`; }
string SUB_IMM(string TO, int NUM) { return `sub ` ~ TO ~ `, ` ~ IMM(NUM) ~ `;`; }
string MUL(string REG) { return `mul ` ~ REG ~ `;`; }

string XOR(string TO, string FROM) { return `xor ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string AND(string TO, string FROM) { return `and ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string OR(string TO, string FROM) { return `or ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string NOT(string REG) { return `not ` ~ REG ~ `;`; }
string ZEROIZE(string REG) { return XOR(REG, REG); }


string ROTL_IMM(string REG, int NUM) { return `rol ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;`; }
string ROTR_IMM(string REG, int NUM) { return `ror ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;`; }
string ADD3_IMM(string TO, string FROM, int NUM) { return `lea ` ~ TO ~ `, ` ~ NUM ~ `[` ~ TO ~ `+` ~ FROM ~ `];`; }