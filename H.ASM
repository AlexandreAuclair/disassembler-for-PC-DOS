PAGE    60,132
TITLE   H - HELLO WORLD PROGRAM
PAGE
;------------------------------------------
;DEFINE STACK SEGMENT
;------------------------------------------
STACK   SEGMENT PARA STACK 'STACK'
        DB      64	 DUP('STACK   ')
STACK   ENDS
;------------------------------------------
;DEFINE DATA SEGMENT
;------------------------------------------
DSEG    SEGMENT PARA PUBLIC 'DATA'
MSG     DB      "HELLO GAMERZ!$"
DSEG    ENDS
;------------------------------------------
;DEFINE CODE SEGMENT
;------------------------------------------
CSEG	SEGMENT	PARA PUBLIC 'CODE'
START	PROC	FAR
		ASSUME 	CS:CSEG,DS:DSEG,SS:STACK
		MOV		AX,DSEG
		MOV		DS,AX
		MOV		AH,09H
		LEA		DX,MSG
		INT		21H
		MOV		AX,4C00H
		INT		21H
START	ENDP
CSEG	ENDS
		END
