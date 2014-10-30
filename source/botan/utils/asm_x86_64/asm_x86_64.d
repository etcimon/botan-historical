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
#define ARRAY8(REG, NUM) 8*(NUM)(REG)
#define ARRAY4(REG, NUM) 4*(NUM)(REG)

#define ASSIGN(TO, FROM) mov FROM, TO

/*
* ALU Operations
*/
#define IMM(VAL) $VAL

#define ADD(TO, FROM) add FROM, TO
#define ADD_LAST_CARRY(REG) adc IMM(0), REG
#define ADD_IMM(TO, NUM) ADD(TO, IMM(NUM))
#define ADD_W_CARRY(TO1, TO2, FROM) add FROM, TO1; adc IMM(0), TO2;
#define SUB_IMM(TO, NUM) sub IMM(NUM), TO
#define MUL(REG) mul REG

#define XOR(TO, FROM) xor FROM, TO
#define AND(TO, FROM) and FROM, TO
#define OR(TO, FROM) or FROM, TO
#define NOT(REG) not REG
#define ZEROIZE(REG) XOR(REG, REG)

#define RETURN_VALUE_IS(V) ASSIGN(%rax, V)

#define ROTL_IMM(REG, NUM) rol IMM(NUM), REG
#define ROTR_IMM(REG, NUM) ror IMM(NUM), REG
#define ADD3_IMM(TO, FROM, NUM) lea NUM(TO,FROM,1), TO

#endif
