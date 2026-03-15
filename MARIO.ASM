DATA SEGMENT
   TAB db 0,0,54h,0,58h,0,68h,0,55h,50h,0eah,0,0fah,0a0h,0aah,0a8h
DATA ENDS

STACK SEGMENT STACK
   DW 32 DUP(0)
STACK ENDS

CODE SEGMENT
   ASSUME CS:CODE, DS:DATA, SS:STACK
   ; INIT SEGMENT REGISTERS
   START:
         MOV AX, DATA
         MOV DS, AX
         CALL SCREEN_INIT

   DRAW_BITMAP:
      PUSH DS
      PUSH ES
         MOV BH, 0ffh   ;X
         MOV BL, 0c0h  ;Y
         CALL GET_SCREEN_POS

         MOV CH, 2  ;WIDTH
         MOV CL, 8  ;HEIGHT

         MOV SI, OFFSET TAB
   DRAW_BITMAP_Y_AGAIN:  ;DS:SI = SOURCE BITMAP
         PUSH DI
         PUSH CX
   DRAW_BITMAP_X_AGAIN:
            MOVSB ;DS:SI -> ES:DI
            DEC CH
            JNZ DRAW_BITMAP_X_AGAIN
         POP CX
         POP DI
         CALL GET_SCREEN_NEXT_LINE
         INC BL
         DEC CL
         JNZ DRAW_BITMAP_Y_AGAIN
      POP ES
      POP DS

   STOP:
         MOV AX, 4C00H
         INT 21H

   SCREEN_INIT:
         MOV AH, 0      ;0=SET VIDEO MODE (AL=MODE)
         MOV AL, 5      ;MODE 4 (CGA 320X200 4 COLOR)
         INT 10H        ; BIOS INT

         MOV AH, 0BH    ;B= SET COLOR PALETTE
         MOV BH, 1      ;1=4 PALETTE MODE
         MOV BL, 1      ;0= WARM COLORS (R,G,Y) 1= COOL COLORS (C,M,W)
         INT 10H        ;BIOS INT

         MOV AH, 0BH    ;B= SET COLOR PALETTE
         MOV BH, 0      ;0 = BRIGHTNESS
         MOV BL, 10H    ;HIGH INTENSITY
         ;MOV BL, 0      ;LOW INTENSITY
         INT 10H
         RET

   GET_SCREEN_POS:   ;BH,BL = X,Y RETURN ES:DI=DESTINATION
      PUSH BX
      PUSH AX
         MOV AH, 0
         MOV AL, BH  ;XPOS
         MOV DI, AX

         MOV AL, BL  ;YPOS
         AND AL, 11111110B

         AND BL, 00000001B
         JZ GET_SCREEN_POS_ODDLINE
         XOR DI, 2000H  ; ALTERNATE LINES AT OFFSET 2000H
   GET_SCREEN_POS_ODDLINE:
         MOV BX, 80  ; 80 BYTES PER 2 LINES (YPOS * 40)
         MUL BX      ; AS LINES ARE INTERLACED
         ADD DI,AX

         MOV AX, 0B800H ;SCREEN BASE
         MOV ES, AX
      POP AX
      POP BX
      RET
   GET_SCREEN_NEXT_LINE:
      PUSH AX
         MOV AX, DI
         AND AX, 2000H  ;SEE IF WE'RE DOING INTERLACED PART
         MOV AX, DI
         JZ GET_SCREEN_NEXT_LINE_DONE
         ADD AX, 80     ;80 BYTES PER LINE (40*2)
   GET_SCREEN_NEXT_LINE_DONE:
         XOR AX, 2000H  ;ALTERNATE LINE AT OFFSET 2000H
         MOV DI, AX
      POP AX
      RET
CODE ENDS
   END START