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
enum ALIGN = ".p2align 4,,15";

/*
* Loop Control
*/
string START_LOOP(string LABEL) {
	return ALIGN ~ `;
			` ~ LABEL  ~ `_LOOP:`;
}

string LOOP_UNTIL_EQ(string REG, int NUM, string LABEL) {
	return `cmpl ` ~ IMM(NUM) ~ `, ` ~ REG ~ `;
			jne ` ~ LABEL ~ `_LOOP;`;
}

string LOOP_UNTIL_LT(REG, NUM, LABEL)() {
	return `cmpl IMM(NUM), REG;	
			jge ` ~ LABEL ~ `_LOOP;`;
}

/*
 Conditional Jumps
*/
string JUMP_IF_ZERO(string REG, string LABEL)() {
	return `cmpl ` ~ IMM(0) ~ `, ` ~ REG ~ `;
			jz ` ~ LABEL ~ `;`;
}

string JUMP_IF_LT(string REG, int NUM, string LABEL) {
	return `cmpl ` ~ IMM(NUM) ~ `, ` ~ REG ~ `;
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
string ARRAY1(string REG, int NUM) { return `(` ~ NUM ~ `)(` ~ REG ~ `)`; }
string ARRAY4(string REG, int NUM) { return `4*(` ~ NUM ~ `)(` ~ REG ~ `)`; }
string ARRAY4_INDIRECT(string BASE, string OFFSET, int NUM) { return `4*(` ~ NUM ~ `)(` ~ BASE ~ `,` ~ OFFSET ~ `,4)`; }
string ARG(int PUSHED, int NUM) { return `4*(` ~ PUSHED ~ `) + ` ~ ARRAY4(ESP, NUM); }

string ASSIGN(string TO, string FROM)() { return `movl ` ~ FROM ~ `, ` ~ TO ~ `;`; }
string ASSIGN_BYTE(string TO, string FROM)() { return `movzbl ` ~ FROM ~ `, ` ~ TO ~ `;`; }

string PUSH(string REG) { return `pushl` ~ REG ~ `;`; }
string POP(string REG) { return `popl` ~ REG ~ `;`; }

string SPILL_REGS() {
	return `PUSH(` ~ EBP ~ `) ;
			PUSH(` ~ EDI ~ `) ;
			PUSH(` ~ ESI ~ `) ;
			PUSH(` ~ EBX ~ `);`;
}

string RESTORE_REGS() {
	return `POP(` ~ EBX ~ `) ;
			POP(` ~ ESI ~ `) ;
			POP(` ~ EDI ~ `) ;
			POP(` ~ EBP ~ `) ;`;
}

/*
* ALU Operations
*/
string IMM(int VAL) { return `$` ~ VAL.to!string; }

string ADD(string TO, string FROM) { return `addl ` ~ FROM ~ `, ` ~ TO ~ `;`; }
string ADD_IMM(string TO, int NUM) { return ADD(TO, IMM(NUM)); }
string ADD_W_CARRY(string TO1, string TO2, string FROM) { return `addl ` ~ FROM ~ `, ` ~ TO1 ~ `; adcl ` ~ IMM(0) ~ `, ` ~ TO2 ~ `;`; }
string SUB_IMM(string TO, int NUM) { return `subl ` ~ IMM(NUM) ~ `, ` ~ TO ~ `;`; }
string ADD2_IMM(string TO, string FROM, int NUM) { return `leal ` ~ NUM(FROM) ~ `, `  ~ TO ~ `;`; }
string ADD3_IMM(string TO, string FROM, int NUM) { return `leal ` ~ NUM(TO,FROM,1) ~ `, ` ~ TO ~ `;`; }
string MUL(string REG) { return `mull ` ~ REG ~ `;`; }

string SHL_IMM(string REG, int SHIFT) { return `shll ` ~ IMM(SHIFT) ~ `, ` ~ REG ~ `;`; }
string SHR_IMM(string REG, int SHIFT) { return `shrl ` ~ IMM(SHIFT) ~ `, ` ~ REG ~ `;`; }
string SHL2_3(string TO, string FROM) { return `leal 0(,` ~ FROM ~ `,8), ` ~ TO ~ `;`; }

string XOR(string TO, string FROM) { return `xorl ` ~ FROM ~ `, ` ~ TO ~ `;`; }
string AND(string TO, string FROM) { return `andl ` ~ FROM ~ `, ` ~ TO ~ `;`; }
string OR(string TO, string FROM) { return `orl ` ~ FROM ~ `, ` ~ TO ~ `;`; }
string NOT(string REG) { return `notl ` ~ REG ~ `;`; }
string ZEROIZE(string REG) { return XOR(REG, REG); }

string ROTL_IMM(string REG, int NUM) { return `roll ` ~ IMM(NUM) ~ `, ` ~ REG ~ `;`; }
string ROTR_IMM(string REG, int NUM) { return `rorl ` ~ IMM(NUM) ~ `, ` ~ REG ~ `;`; }
string BSWAP(string REG) { return `bswapl ` ~ REG ~ `;`; }