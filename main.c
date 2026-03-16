#include <stdio.h>
#include <stdlib.h>
#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint16_t signature;      // "MZ"
    uint16_t bytesLastPage;
    uint16_t pages;
    uint16_t relocations;
    uint16_t headerSize;     // en paragraphs (16 bytes)
    uint16_t minAlloc;
    uint16_t maxAlloc;
    uint16_t ss;
    uint16_t sp;
    uint16_t checksum;
    uint16_t ip;
    uint16_t cs;
    uint16_t relocTable;
    uint16_t overlay;
} EXEHeader;

typedef struct {
    uint8_t* data;
    long length;
} FileData;

typedef struct {
    char *name;
    uint8_t modrm;      // 0: nothing, 1: modrm value 2: immediat 3:addr 4:rel16 5:seg:a16 6: rel8
    uint8_t word;       // 0: byte, 1: word 
    uint8_t direction;  // 0: register to register/memory, 1: r/m to reg 2: immediat to r/m 3: immediat8 to r/m 16bit 4: seg reg to r/m 5: r/m to seg reg 6: r16, m32 
                        // 7: r/m shift by 1 8: r/m shift by CL 9: only r/m
} Opcode;

Opcode table[256] = {
    [0x00] = {"ADD",1,0,0},
    [0x01] = {"ADD",1,1,0},
    [0x02] = {"ADD",1,0,1},
    [0x03] = {"ADD",1,1,1},

    [0x04] = {"ADD AL,",2,0,0},
    [0x05] = {"ADD AX,",2,1,0},

    [0x06] = {"PUSH ES",0,0,0},
    [0x07] = {"POP ES",0,0,0},

    [0x08] = {"OR",1,0,0},
    [0x09] = {"OR",1,1,0},
    [0x0A] = {"OR",1,0,1},
    [0x0B] = {"OR",1,1,1},
    
    [0x0C] = {"OR AL,",2,0,0},
    [0x0D] = {"OR AX,",2,1,0},
    
    [0x0E] = {"PUSH CS",0,0,0},
    [0x0F] = {"POP CS",0,0,0},

    [0x10] = {"ADC",1,0,0},
    [0x11] = {"ADC",1,1,0},
    [0x12] = {"ADC",1,0,1},
    [0x13] = {"ADC",1,1,1},

    [0x14] = {"ADC AL,",2,0,0},
    [0x15] = {"ADC AX,",2,1,0},

    [0x16] = {"PUSH SS",0,0,0},
    [0x17] = {"POP SS",0,0,0},

    [0x18] = {"SBB",1,0,0},
    [0x19] = {"SBB",1,1,0},
    [0x1A] = {"SBB",1,0,1},
    [0x1B] = {"SBB",1,1,1},
    
    [0x1C] = {"SBB AL,",2,0,0},
    [0x1D] = {"SBB AX,",2,1,0},
    
    [0x1E] = {"PUSH DS",0,0,0},
    [0x1F] = {"POP DS",0,0,0},

    [0x20] = {"AND",1,0,0},
    [0x21] = {"AND",1,1,0},
    [0x22] = {"AND",1,0,1},
    [0x23] = {"AND",1,1,1},

    [0x24] = {"AND AL,",2,0,0},
    [0x25] = {"AND AX,",2,1,0},

    [0x26] = {"ES:",0,0,0},
    [0x27] = {"DAA",0,0,0},

    [0x28] = {"SUB",1,0,0},
    [0x29] = {"SUB",1,1,0},
    [0x2A] = {"SUB",1,0,1},
    [0x2B] = {"SUB",1,1,1},
    
    [0x2C] = {"SUB AL,",2,0,0},
    [0x2D] = {"SUB AX,",2,1,0},

    [0x2E] = {"CS:",0,0,0},
    [0x2F] = {"DAS",0,0,0},

    [0x30] = {"XOR",1,0,0},
    [0x31] = {"XOR",1,1,0},
    [0x32] = {"XOR",1,0,1},
    [0x33] = {"XOR",1,1,1},

    [0x34] = {"XOR AL,",2,0,0},
    [0x35] = {"XOR AX,",2,1,0},

    [0x36] = {"SS:",0,0,0},
    [0x37] = {"AAA",0,0,0},

    [0x38] = {"CMP",1,0,0},
    [0x39] = {"CMP",1,1,0},
    [0x3A] = {"CMP",1,0,1},
    [0x3B] = {"CMP",1,1,1},
    
    [0x3C] = {"CMP AL,",2,0,0},
    [0x3D] = {"CMP AX,",2,1,0},

    [0x3E] = {"DS:",0,0,0},
    [0x3F] = {"AAS",0,0,0},

    [0x40] = {"INC AX",0,0,0},
    [0x41] = {"INC CX",0,0,0},
    [0x42] = {"INC DX",0,0,0},
    [0x43] = {"INC BX",0,0,0},
    [0x44] = {"INC SP",0,0,0},
    [0x45] = {"INC BP",0,0,0},
    [0x46] = {"INC SI",0,0,0},
    [0x47] = {"INC DI",0,0,0},

    [0x48] = {"DEC AX",0,0,0},
    [0x49] = {"DEC CX",0,0,0},
    [0x4A] = {"DEC DX",0,0,0},
    [0x4B] = {"DEC BX",0,0,0},
    [0x4C] = {"DEC SP",0,0,0},
    [0x4D] = {"DEC BP",0,0,0},
    [0x4E] = {"DEC SI",0,0,0},
    [0x4F] = {"DEC DI",0,0,0},

    [0x50] = {"PUSH AX",0,0,0},
    [0x51] = {"PUSH CX",0,0,0},
    [0x52] = {"PUSH DX",0,0,0},
    [0x53] = {"PUSH BX",0,0,0},
    [0x54] = {"PUSH SP",0,0,0},
    [0x55] = {"PUSH BP",0,0,0},
    [0x56] = {"PUSH SI",0,0,0},
    [0x57] = {"PUSH DI",0,0,0},

    [0x58] = {"POP AX",0,0,0},
    [0x59] = {"POP CX",0,0,0},
    [0x5A] = {"POP DX",0,0,0},
    [0x5B] = {"POP BX",0,0,0},
    [0x5C] = {"POP SP",0,0,0},
    [0x5D] = {"POP BP",0,0,0},
    [0x5E] = {"POP SI",0,0,0},
    [0x5F] = {"POP DI",0,0,0},

    [0x70] = {"JO",6,0,0},
    [0x71] = {"JNO",6,0,0},
    [0x72] = {"JC",6,0,0},
    [0x73] = {"JNC",6,0,0},
    [0x74] = {"JE",6,0,0},
    [0x75] = {"JNE",6,0,0},
    [0x76] = {"JBE",6,0,0},
    [0x77] = {"JA",6,0,0},
    [0x78] = {"JS",6,0,0},
    [0x79] = {"JNS",6,0,0},
    [0x7A] = {"JP",6,0,0},
    [0x7B] = {"JNP",6,0,0},
    [0x7C] = {"JL",6,0,0},
    [0x7D] = {"JGE",6,0,0},
    [0x7E] = {"JLE",6,0,0},
    [0x7F] = {"JG",6,0,0},

    [0x80] = {"ALU1",1,0,2},
    [0x81] = {"ALU1",1,1,2},
    [0x82] = {"ALU1",1,0,2},
    [0x83] = {"ALU1",1,1,3},

    [0x84] = {"TEST",1,0,0},
    [0x85] = {"TEST",1,1,0},

    [0x86] = {"XCHG",1,0,1},
    [0x87] = {"XCHG",1,1,1},

    [0x88] = {"MOV",1,0,0},
    [0x89] = {"MOV",1,1,0},
    [0x8A] = {"MOV",1,0,1},
    [0x8B] = {"MOV",1,1,1},
    [0x8C] = {"MOV",1,1,4},

    [0x8D] = {"LEA",1,1,1},

    [0x8E] = {"MOV",1,1,5},

    [0x8F] = {"POP",1,1,0},

    [0x90] = {"NOP",0,0,0},

    [0x91] = {"XCHG AX,CX",0,0,0},
    [0x92] = {"XCHG AX,DX",0,0,0},
    [0x93] = {"XCHG AX,BX",0,0,0},
    [0x94] = {"XCHG AX,SP",0,0,0},
    [0x95] = {"XCHG AX,BP",0,0,0},
    [0x96] = {"XCHG AX,SI",0,0,0},
    [0x97] = {"XCHG AX,DI",0,0,0},

    [0x98] = {"CBW",0,0,0},
    [0x99] = {"CWD",0,0,0},

    [0x9A] = {"CALL",5,1,0},
    
    [0x9B] = {"WAIT",0,0,0},
    
    [0x9C] = {"PUSHF",0,0,0},
    [0x9D] = {"POPF",0,0,0},
    [0x9E] = {"SAHF",0,0,0},
    [0x9F] = {"LAHF",0,0,0},

    [0xA0] = {"MOV AL,",3,0,0},
    [0xA1] = {"MOV AX,",3,1,0},
    [0xA2] = {"MOV",3,0,1},
    [0xA3] = {"MOV",3,1,1},

    [0xA4] = {"MOVSB",0,0,0},
    [0xA5] = {"MOVSW",0,0,0},

    [0xA6] = {"CMPSB",0,0,0},
    [0xA7] = {"CMPSW",0,0,0},

    [0xA8] = {"TEST AL,",0,0,0},
    [0xA9] = {"TEST AX,",0,1,0},
    
    [0xAA] = {"STOSB",0,0,0},
    [0xAB] = {"STOSW",0,0,0},

    [0xAC] = {"LODSB",0,0,0},
    [0xAD] = {"LODSW",0,0,0},

    [0xAE] = {"SCASB",0,0,0},
    [0xAF] = {"SCASW",0,0,0},

    [0xB0] = {"MOV AL,",2,0,0},
    [0xB1] = {"MOV CL,",2,0,0},
    [0xB2] = {"MOV DL,",2,0,0},
    [0xB3] = {"MOV BL,",2,0,0},
    [0xB4] = {"MOV AH,",2,0,0},
    [0xB5] = {"MOV CH,",2,0,0},
    [0xB6] = {"MOV DH,",2,0,0},
    [0xB7] = {"MOV BH,",2,0,0},
    [0xB8] = {"MOV AX,",2,1,0},
    [0xB9] = {"MOV CX,",2,1,0},
    [0xBA] = {"MOV DX,",2,1,0},
    [0xBB] = {"MOV BX,",2,1,0},
    [0xBC] = {"MOV SP,",2,1,0},
    [0xBD] = {"MOV BP,",2,1,0},
    [0xBE] = {"MOV SI,",2,1,0},
    [0xBF] = {"MOV DI,",2,1,0},
    
    [0xC2] = {"RET",2,1,0},
    [0xC3] = {"RET",0,0,0},

    [0xC4] = {"LES",1,1,6},
    [0xC5] = {"LDS",1,1,6},

    [0xC6] = {"MOV",1,0,2},
    [0xC7] = {"MOV",1,1,2},

    [0xCA] = {"RETF",2,1,0},
    [0xCB] = {"RETF",0,0,0},

    [0xCC] = {"INT 3",0,0,0},
    [0xCD] = {"INT",2,0,0},

    [0xCE] = {"INTO",0,0,0},

    [0xCF] = {"IRET",0,0,0},

    [0xD0] = {"ROT",1,0,7},
    [0xD1] = {"ROT",1,1,7},
    [0xD2] = {"ROT",1,0,8},
    [0xD3] = {"ROT",1,1,8},

    [0xD4] = {"AAM",2,0,0},
    [0xD5] = {"AAD",2,0,0},

    [0xD6] = {"SALC",0,0,0},

    [0xD7] = {"XLAT",0,0,0},

    [0xD8] = {"ESC 0",0,0,0},
    [0xD9] = {"ESC 1",0,0,0},
    [0xDA] = {"ESC 2",0,0,0},
    [0xDB] = {"ESC 3",0,0,0},
    [0xDC] = {"ESC 4",0,0,0},
    [0xDD] = {"ESC 5",0,0,0},
    [0xDE] = {"ESC 6",0,0,0},
    [0xDF] = {"ESC 7",0,0,0},

    [0xE0] = {"LOOPNZ",6,0,0},
    [0xE1] = {"LOOPZ",6,0,0},
    [0xE2] = {"LOOP",6,0,0},

    [0xE3] = {"JCXZ",2,0,0},

    [0xE4] = {"IN AL,",2,0,0},
    [0xE5] = {"IN AX,",2,1,0},
    [0xE6] = {"OUT",2,0,0},
    [0xE7] = {"OUT",2,1,0},

    [0xE8] = {"CALL",4,1,0},

    [0xE9] = {"JMP",4,1,0},
    [0xEA] = {"JMP",5,1,0},
    [0xEB] = {"JMP",6,0,0},

    [0xEC] = {"IN AL,[DX]",0,0,0},
    [0xED] = {"IN AX,[DX]",0,0,0},
    [0xEE] = {"OUT [DX],AL",0,0,0},
    [0xEF] = {"OUT [DX],AX",0,0,0},

    [0xF0] = {"LOCK",0,0,0},

    [0xF2] = {"REPNE",0,0,0},
    [0xF3] = {"REP",0,0,0},

    [0xF4] = {"HLT",0,0,0},

    [0xF5] = {"CMC",0,0,0},

    [0xF6] = {"ALU2",1,0,0}, // my observation make me think that MUL reg = 
    [0xF7] = {"ALU2",1,1,0}, // ALU2 reg,SP and DIV reg = ALU2 reg,SI

    [0xF8] = {"CLC",0,0,0},
    [0xF9] = {"STC",0,0,0},
    [0xFA] = {"CLI",0,0,0},
    [0xFB] = {"STI",0,0,0},
    [0xFC] = {"CLD",0,0,0},
    [0xFD] = {"STD",0,0,0},

    [0xFE] = {"MISC",1,0,9},
    [0xFF] = {"MISC",1,1,9},
};

const char *reg16[8] =
{
    "AX","CX","DX","BX",
    "SP","BP","SI","DI"
};

const char *reg8[8] =
{
    "AL","CL","DL","BL",
    "AH","CH","DH","BH"
};

const char *segreg[4] =
{
    "ES","CS","SS","DS"
};

const char *ea[8] =
{
    "BX+SI",
    "BX+DI",
    "BP+SI",
    "BP+DI",
    "SI",
    "DI",
    "BP",
    "BX"
};

const char *_ALU1[8] = {
    "ADD",
    "OR",
    "ADC",
    "SBB",
    "AND",
    "SUB",
    "XOR",
    "CMP"
};

const char *_ALU2[8] = {
    "TEST",
    "TEST",
    "NOT",
    "NEG",
    "MUL",
    "IMUL",
    "DIV",
    "IDIV"
};

const char *_ROT[8] = {
    "ROL",
    "ROR",
    "RCL",
    "RCR",
    "SHL",
    "SHR",
    "SAL",
    "SAR"
};

const char *_MISC[8] = {
    "INC",
    "DEC",
    "CALL",
    "CALL",
    "JMP",
    "JMP",
    "PUSH",
    "PUSH"
};

int decode_rm(FILE *f, uint8_t *code, int *ip,
              uint8_t modrm, uint8_t word, uint8_t direction)
{
    uint8_t mod = modrm >> 6;
    uint8_t reg = (modrm >> 3) & 7;
    uint8_t rm  = modrm & 7;

    uint8_t *reg_name = NULL;
    uint8_t *rm_name  = NULL;

    /* register decoding */

    if(direction == 4 || direction == 5)
        reg_name = segreg[reg & 3];
    else
        reg_name = word ? reg16[reg] : reg8[reg];

    /* r/m decoding */

    if(mod == 3)
        rm_name = word ? reg16[rm] : reg8[rm];

    /* memory operand */

    

    if(mod != 3)
        rm_name = ""; /* already printed */

    /* operand decoding */

    switch(direction)
    {

    case 0: /* reg -> r/m */
        if(mod == 3)
            fprintf(f,"%s,%s", rm_name, reg_name);
        else
            fprintf(f,",%s", reg_name);
        return 1;
        break;

    case 1: /* r/m -> reg */
        if(mod == 3){
            fprintf(f,"%s,%s", reg_name, rm_name);
            return 1;
        }
        else
            fprintf(f,"%s,", reg_name);
        break;

    case 2: /* imm -> r/m */

        if(mod == 3){
            fprintf(f,"%s,", rm_name);
            uint16_t imm = word ?
                *(uint16_t*)(code + *ip) :
                *(uint8_t*)(code + *ip);

            fprintf(f,"%Xh", imm);

            *ip += word ? 2 : 1;
            return 1;
        }
        
        break;

    case 3: /* imm8 -> r/m16 (opcode 83) */

        if(mod == 3){}
            fprintf(f,"%s,", rm_name);

        uint8_t imm8 = *(uint8_t*)(code + *ip);
        fprintf(f,"%02xh", imm8);
        *ip += 1;
        return 1;
        break;

    case 4: /* seg -> r/m */

        if(mod == 3)
            fprintf(f,"%s,%s", rm_name, reg_name);
        else
            fprintf(f,",%s", reg_name);
        return 1;
        break;

    case 5: /* r/m -> seg */

        if(mod == 3){
            fprintf(f,"%s,%s", reg_name, rm_name);
            return 1;
        }
        else
            fprintf(f,"%s,", reg_name);
        
        break;

    case 6: /* r16 , m32 (LES/LDS) */

        if(mod == 3){
            fprintf(f,"%s,%s", reg16[reg], rm_name);
            return 1;
        }
        else
            fprintf(f,"%s,", reg16[reg]);

        break;

    case 7: /* shift by 1 */

        if(mod == 3)
            fprintf(f,"%s,1", rm_name);
        else
            fprintf(f,",1");
        return 1;
        break;

    case 8: /* shift by CL */

        if(mod == 3)
            fprintf(f,"%s,CL", rm_name);
        else
            fprintf(f,",CL");
        return 1;
        break;

    case 9: /* only r/m (INC/DEC/PUSH etc groups) */

        if(mod == 3){
            fprintf(f,"%s", rm_name);
            return 1;
        }
        break;
    }

    if(mod == 0 && (rm == 0 || rm == 1 || rm == 4 || rm == 5 || rm == 6 || rm == 7)){        
        fprintf(f, "DS:");
        *ip+=1;
    }

    if(mod == 0 && (rm == 2 || rm == 3)){        
        fprintf(f, "SS:");
        *ip+=1;
    }

    if((mod == 1 || mod == 2) && (rm == 0 || rm == 1 || rm == 4 || rm == 5 || rm == 7)){        
        fprintf(f, "DS:");
        *ip+=1;
    }

    if((mod == 1 || mod == 2) && (rm == 2 || rm == 3 || rm == 6)){        
        fprintf(f, "SS:");
        *ip+=1;
    }

    if(mod != 3)
    {
        fprintf(f,"[");

        if(mod == 0 && rm == 6)
        {
            uint16_t disp = *(uint16_t*)(code + *ip);
            fprintf(f,"%04Xh", disp);
            *ip += 2;
        }
        else
        {
            fprintf(f,"%s", ea[rm]);

            if(mod == 1)
            {
                int8_t disp = *(int8_t*)(code + *ip);
                fprintf(f,"%+dh", disp);
                *ip += 1;
            }

            if(mod == 2)
            {
                int16_t disp = *(int16_t*)(code + *ip);
                fprintf(f,"%+dh", disp);
                *ip += 2;
            }
        }

        fprintf(f,"]");

        if(direction == 2){
            uint16_t imm = word ?
                *(uint16_t*)(code + *ip) :
                *(uint8_t*)(code + *ip);

            fprintf(f,",%Xh", imm);

            *ip += word ? 2 : 1;
        }
    }

    return 0;
}

int checkForGroup(FILE *f, uint8_t *code, int *ip){
    uint8_t modrm = code[(*ip)+1];
    uint8_t operandePlus = (modrm >> 3) & 7;
    switch (code[*ip])
    {
    case 0x80:
        fprintf(f,"%s ",_ALU1[operandePlus]);
        return 1;
        break;
    case 0x81:
        fprintf(f,"%s ",_ALU1[operandePlus]);
        return 1;
        break;
    case 0x82:
        fprintf(f,"%s ",_ALU1[operandePlus]);
        return 1;
        break;
    case 0x83:
        fprintf(f,"%s ",_ALU1[operandePlus]);
        return 1;
        break;
    case 0x8C:
        fprintf(f,"MOV ");
        return 1;
        break;
    case 0x8D:
        fprintf(f,"MOV ");
        return 1;
        break;
    case 0x8F:
        fprintf(f,"POP ");
        return 1;
        break;
    case 0xC6:
        fprintf(f,"MOV ");
        return 1;
        break;
    case 0xC7:
        fprintf(f,"MOV ");
        return 1;
        break;
    case 0xD0:
        fprintf(f,"%s ", _ROT[operandePlus]);
        return 1;
        break;
    case 0xD1:
        fprintf(f,"%s ", _ROT[operandePlus]);
        return 1;
        break;
    case 0xD2:
        fprintf(f,"%s ", _ROT[operandePlus]);
        return 1;
        break;
    case 0xD3:
        fprintf(f,"%s ", _ROT[operandePlus]);
        return 1;
        break;
    case 0xF6:
        fprintf(f,"%s ", _ALU2[operandePlus]);
        return 1;
        break;
    case 0xF7:
        fprintf(f,"%s ", _ALU2[operandePlus]);
        return 1;
        break;
    case 0xFE:
        fprintf(f,"%s ", _MISC[operandePlus]);
        return 1;
        break;
    case 0xFF:
        fprintf(f,"%s ", _MISC[operandePlus]);
        return 1;
        break;
    }

    return 0;
}


FileData readFile(const char* filePath) 
{
    FileData result = {};
    FILE *file = fopen(filePath, "rb");
    if(!file)
    {
        fprintf(stderr, "cannot open file: %s\n", filePath);
        return result;
    }

    // Seek the end to determine file size
    fseek(file, 0, SEEK_END);
    long length = ftell(file);
    rewind(file);

    // Allocate buffer for content (+1 for null terminator)
    uint8_t* buffer = (char*)malloc(length+1);
    if(!buffer) 
    {
        fprintf(stderr, "memory allocation failed\n");
        fclose(file);
        return result;
    }

    size_t readSize = fread(buffer, 1, length, file);
    buffer[readSize] = '\0'; // Null-terminate the string
    fclose(file);

    result.data = buffer;
    result.length = length;
    return result;
}

void writeFile(const char *filepath, uint8_t *code, int size) {
    FILE *file = fopen(filepath,"w");

    int ip = 0;

    while(ip < size)
    {
        Opcode *op = &table[code[ip]];

        fprintf(file, "%04X  ",ip);

        if(op->name == NULL){
            fprintf(file, "DB %02X\n",op);
            ip++;
            continue;
        }

        if(!checkForGroup(file, code, &ip)){
            fprintf(file, "%s ", op->name);
            ip++;
        }
        else{
            ip++;
        }
        
        if(op->modrm == 1) {
            uint8_t modrm = code[ip];
            if(decode_rm(file, code, &ip, modrm, op->word, op->direction))
                ip++;
        }

        if(op->modrm == 2){
            if(!op->word){
                fprintf(file, "%02xh", code[ip]);
                ip++;
            }
            else{
                uint16_t v = *(uint16_t*)(code+ip);
                fprintf(file,"%04xh", v);
                ip+=2;
            }
        }

        if(op->modrm == 3){
            fprintf(file,"[");
            uint16_t v = *(uint16_t*)(code+ip);
            fprintf(file,"%04xh", v);
            fprintf(file,"]");

            if(op->direction) {
                if(op->word)
                    fprintf(file,",AX");
                else
                    fprintf(file,",AL");
                
            }
            
            ip+=2;
        }

        if(op->modrm == 4){
            uint16_t v = *(uint16_t*)(code+ip);
            fprintf(file,"%04xh", v+ip+2);
            ip+=2;
        }

        if(op->modrm == 5){
            uint16_t v = *(uint16_t*)(code+ip);
            ip+=2;
            uint16_t v2 = *(uint16_t*)(code+ip);
            fprintf(file,"%04xh:%04xh", v2,v);
            ip+=2;
        }

        if(op->modrm == 6){
            int8_t v = *(int8_t*)(code+ip);
            fprintf(file, "%04xh", ip+1+v);
            ip++;
        }
        
        fprintf(file, "\n");
        
    }

    fclose(file);
}



void main(int argc,char **argv){
    FileData f = readFile(argv[1]);

    EXEHeader *exe = (EXEHeader*)f.data;

    int offset = exe->headerSize * 16;

    writeFile("assembly.txt", f.data+offset, f.length-offset);
    
}