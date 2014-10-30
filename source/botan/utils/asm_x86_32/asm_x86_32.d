/*
* Assembly Macros for 32-bit x86
* (C) 1999-2008 Jack Lloyd
*
* Distributed under the terms of the botan license.
*/
module botan.utils.asm_x86_32.asm_x86_32;
import std.conf : to;
/*
* General/Global Macros
*/
enum ALIGN = "align 16";

/*
* Loop Control
*/
string START_LOOP(string LABEL) {
	return ALIGN ~ `;
			` ~ LABEL  ~ `_LOOP:`;
}

string LOOP_UNTIL_EQ(string REG, int NUM, string LABEL) {
	return `cmp  ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;
			jne ` ~ LABEL ~ `_LOOP;`;
}

string LOOP_UNTIL_LT(REG, NUM, LABEL)() {
	return `cmp ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;	
			jge ` ~ LABEL ~ `_LOOP;`;
}

/*
 Conditional Jumps
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
enum EAX = `EAX`;
enum EBX = `EBX`;
enum ECX = `ECX`;
enum EDX = `EDX`;
enum EBP = `EBP`;
enum EDI = `EDI`;
enum ESI = `ESI`;
enum ESP = `ESP`;

/*
* Memory Access Operations
*/
string ARRAY4(string REG, int NUM) { return `[` ~ REG ~ ` + 4*` ~ NUM ~ `]`; }
string ARRAY4_INDIRECT(string BASE, string OFFSET, int NUM) { return `4*` ~ NUM ~ `[` ~ BASE ~ ` + ` ~ OFFSET ~ ` * 4]`; }
string ARG(int PUSHED, int NUM) { return `4*` ~ PUSHED ~ ` + ` ~ ARRAY4(ESP, NUM); }

string ASSIGN(string TO, string FROM) { return `mov ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string ASSIGN_BYTE(string TO, string FROM) { return `mov ` ~ TO ~ `, ` ~ FROM ~ `;`; }

string PUSH(string REG) { return `push` ~ REG ~ `;`; }
string POP(string REG) { return `pop` ~ REG ~ `;`; }

string SPILL_REGS() {
	return `PUSH(` ~ EBP ~ `)
			PUSH(` ~ EDI ~ `)
			PUSH(` ~ ESI ~ `)
			PUSH(` ~ EBX ~ `)`;
}

string RESTORE_REGS() {
	return `POP(` ~ EBX ~ `)
			POP(` ~ ESI ~ `)
			POP(` ~ EDI ~ `)
			POP(` ~ EBP ~ `)`;
}

/*
* ALU Operations
*/
string IMM(int VAL) { return VAL.to!string; }

string ADD(string TO, string FROM) { return `add ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string ADD_IMM(string TO, int NUM) { return ADD(TO, IMM(NUM)); }
string ADD_W_CARRY(string TO1, string TO2, string FROM) { return `add ` ~ TO1 ~ `, ` ~ FROM ~ `; adcl ` ~ TO2 ~ `, ` ~ IMM(0) ~ `;`; }
string SUB_IMM(string TO, int NUM) { return `sub ` ~ TO ~ `, ` ~ IMM(NUM) ~ `;`; }
string ADD2_IMM(string TO, string FROM, int NUM) { return `lea `  ~ TO ~ `, ` ~ NUM ~ `*` ~ FROM ~ `;`; }
string ADD3_IMM(string TO, string FROM, int NUM) { return `lea ` ~ TO ~ `, ` ~ NUM ~ `[` ~ TO ~ `+` ~ FROM ~ `];`; }
string MUL(string REG) { return `mul ` ~ REG ~ `;`; }

string SHL_IMM(string REG, int SHIFT) { return `shl ` ~ REG ~ `, ` ~ IMM(SHIFT) ~ `;`; }
string SHR_IMM(string REG, int SHIFT) { return `shr ` ~ REG ~ `, ` ~ IMM(SHIFT) ~ `;`; }
string SHL2_3(string TO, string FROM) { return `lea ` ~ TO ~ `, [` ~ FROM ~ `*8];`; }

string XOR(string TO, string FROM) { return `xor ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string AND(string TO, string FROM) { return `and ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string OR(string TO, string FROM) { return `or ` ~ TO ~ `, ` ~ FROM ~ `;`; }
string NOT(string REG) { return `not ` ~ REG ~ `;`; }
string ZEROIZE(string REG) { return XOR(REG, REG); }

string ROTL_IMM(string REG, int NUM) { return `rol ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;`; }
string ROTR_IMM(string REG, int NUM) { return `ror ` ~ REG ~ `, ` ~ IMM(NUM) ~ `;`; }
string BSWAP(string REG) { return `bswap ` ~ REG ~ `;`; }