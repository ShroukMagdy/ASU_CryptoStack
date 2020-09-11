/***************************************************************************************
 *  File:HAS_Keypad_Password.c
 *  Copyright (C) 2018 ALHASAN ALKHATIB
 *
 *  date: June,2018
 *  Author: ALHASAN ALKHATIB
 *
 *  Description: Password security System To control a Relay
 *               using 16*16 Keypad and 16*2 LCD Display
 *               with ARM CORTEX -M4 TM4C123G Microprocessor (Source file)
 *
 ***************************************************************************************/


#include <stdint.h>
#include <stdbool.h>
#include "inc/hw_types.h"
#include "inc/hw_memmap.h"
#include "driverlib/sysctl.h"
#include "driverlib/gpio.h"
#include "inc/hw_gpio.h"
#include "driverlib/interrupt.h"
#include "inc/hw_ints.h"
#include "HASLCD_JR.h"
#include "HAS_Keypad_Password.h"


uint8_t Password[4]="0000"; //the virtual password
uint8_t EnteredPassword[4];
uint8_t col=4; // will be used in keypad_wait fun. for open and close the pins of columuns in the order
uint8_t inttertuptvalue=0; //will be used to know which pin is intterrupted
uint8_t X;//the row number of selected switch
uint8_t Y;//the colunm number of selected switch
uint8_t Enterd_Password_Counter=0;
uint8_t Password_Confirm_Counter=0;
uint8_t NewPassword_Counter=0;
bool NewPasswordControl=0;
bool CorrectPasswordWait=0;

/*
 * the 16*16 Keypad buttons
 * */
uint8_t MKeyPad[4][4]= {
		  {'1','2','3','A'},
		  {'4','5','6','B'},
		  {'7','8','9','C'},
		  {'*','0','#','D'}
		};


////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void KeyPad_Lcd_Setup()
{

	 has_lcd_erase();
	 has_lcd_write(1,1,"Enter the ");
	 has_lcd_write(2,1,"Password:");

}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
bool KeyPad_PassWord_Confirm()
{    bool PassWord_Confirm =false;
	uint8_t b=0;//will be used in for loop
   /*
    * if the new password was reset (CounterNewPassword==4) this statement will be implemented
    *
    * */
   if(NewPassword_Counter==4){
	   NewPasswordControl=0;
	   NewPassword_Counter=0; //Reset to 0 for next Password Reseting(if it is happened)
	   has_lcd_erase();
	   has_lcd_write(1,1,"DONE");
	   SysCtlDelay(SysCtlClockGet()/2);
	   KeyPad_Lcd_Setup();//preparing to enter the password after reseting

   }
   /*
    * else the Entered password will be confirmed if its correct or not
    * by comparing Password and EnteredPassword
    *
    * */
   else{
	     for(b=0;b<4;b++){
	   	     if(EnteredPassword[b]==Password[b]){
	   	    	Password_Confirm_Counter++;
	   	     }
	     }
	     /* if Entered Password is correct:
	      * in this statement PF1(RELAY or RGB RED) will be set to 1(logic)
	      * CorrectPasswordWait will be set to 1  to disallow enter a password exept reseting password(look at tge void KeyPad_int())
	      * */
         if(Password_Confirm_Counter==4)
         {   PassWord_Confirm=true;
        	 has_lcd_erase();
        	 has_lcd_write(1,1,"correct Password");
        	 SysCtlDelay(SysCtlClockGet()/2);
        	 CorrectPasswordWait=1;
        	 has_lcd_erase();
        	 has_lcd_write(1,1,"LED IS ");
        	 has_lcd_write(2,1,"Lighting");
        	 GPIOPinWrite(GPIO_PORTF_BASE,GPIO_PIN_1,2);
         }
         /*
          * else if its not correct prepar to try again
          * */
         else
         {   PassWord_Confirm=false;
        	 has_lcd_erase();
        	 has_lcd_write(1,1,"incorrect Password");
        	 has_lcd_write(2,1,"Try again");


        	 SysCtlDelay(SysCtlClockGet()/2);
        	 KeyPad_Lcd_Setup();

         }

         Enterd_Password_Counter=0;
         Password_Confirm_Counter=0;

   	   }

return PassWord_Confirm;

}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
/*
 * to calculate 2^x
 * */

uint8_t power(uint8_t x)
{
	uint8_t y=1;
	uint8_t i=0;
	for(i=0;i<x;i++)
	{
		y=y*2;
	}
return y;
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void KeyPad_wait()
{
	/*
	 * while the digits of password (the correct password or Enterd password )is lease than 4 digit
	 * the operation of set-clear columns pins in order will countinues
	 */

	while((Enterd_Password_Counter<4)&&(NewPassword_Counter<4)){
	   for(col=4;col<=7;col++){
	     GPIOPinWrite(GPIO_PORTC_BASE,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7,240-power(col));//look to the comment below
	     /*
	      *(2^4)+(2^5)+(2^6)+(2^7)=240
	      *(240-2^COl)operation sets the pins(4-7)to 1(logic) except the pin of COL ( if Col=4 --->PIN4=0(logic) )
	      */
	     SysCtlDelay(20000);//by testing 20000 MS is a good duration between Entering the digits

	   }
	}
}
////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void NewPasswordWait()
{
	/*
	 * to Clear the pin of Relay(or RGB RED) and'CorrectPasswordWait' if the password is changed after Turning on the PIN(PF1)
	 *
	 * */
	 GPIOPinWrite(GPIO_PORTF_BASE,GPIO_PIN_1,0);
	 CorrectPasswordWait=0;

	 /*
	  * Preparing LCD to New Password
	  * */
	 has_lcd_erase();
	 has_lcd_write(1,1,"Enter new pass");
	 has_lcd_position(2,1);

	 NewPasswordControl=1;//To determine the entered char if it belongs to the Password or to a Entered Passowrd

}
/////////////////////////////////////////////////////////////////////////////////////
/*
 * to take log2 of x
 * */

uint8_t ln(uint8_t x)
{
	uint8_t y=0;
		while(x!=1)
		{
			x=x/2;
			y++;
		}

return y;
}
///////////////////////////////////////////////////////////////////////////////

void KeyPad_int()
{
/*
 * when on of pins4to7 of PORTA is fulling to 0(interrupting) the Program Counter will Indicate to this function
 *
 */

	inttertuptvalue=GPIOIntStatus(GPIO_PORTA_BASE,false); //which pin is interrupted (EX: if pin4---> inttertuptvalue=16)

    X=ln(inttertuptvalue)-4;//look below
    /*
     * taking log2 of inttertupvalue will give the pins number
     * and then shifting by -4 will give the real number of Keypads row
     */

    Y=col-4;//shifting (EX 4 to 0 , 7 to 3)will give the real number of Keypads column

    /*
     * if the System waits a password (CorrectPasswordWait==0) the entered charecter will be sent to LCD
     *
     * */
    if(!CorrectPasswordWait){
    has_lcd_sendchar(MKeyPad[X][Y]);
    //has_lcd_sendchar('*');
    }
    SysCtlDelay(SysCtlClockGet()/4);//choosen by testing


    /*
     * this 8 lines below are written to detect the holding of #
     * that will allow to change a virtual password
     * */
    if (MKeyPad[X][Y]=='#'){
        SysCtlDelay(20000);

        /*
         *   @if the holding of # crosses a specific duration the PC will go to NewPasswordWait() function
         * */
        if(GPIOPinRead(GPIO_PORTA_BASE,inttertuptvalue)==0){
            SysCtlDelay(SysCtlClockGet());

         	while(GPIOPinRead(GPIO_PORTA_BASE,inttertuptvalue)==0){
         		NewPasswordWait();
         	}
        }

        /*
         * @else '#' will be a typical charecter
         * */

        else if(!CorrectPasswordWait){
        	PasswordTypeControl();
        }
    }
    /*
     * if '#' is not has been entered in the first place
     * */
    else if(!CorrectPasswordWait){
    	PasswordTypeControl();
    }

    GPIOIntClear(GPIO_PORTA_BASE,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7);
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void PasswordTypeControl()
{
	/*
	 * if MKeyPad belongs to password(NewPasswordControl==1) send it to passwords array
	 * else send it to EnterdPasswords array
	 * */

	  if(NewPasswordControl){
	              Password[NewPassword_Counter]=MKeyPad[X][Y];
	              NewPassword_Counter++;
	  }
	  else{
	           EnteredPassword[Enterd_Password_Counter]=MKeyPad[X][Y];
	           Enterd_Password_Counter++;
	           /*
	           has_lcd_write(2,1,'*');
	           has_lcd_position(2,Enterd_Password_Counter+1);
	           */
	  }
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
void KeyPad_Setup()
{
	IntMasterEnable();
			SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOF);//Enable the peripheral of GPIOPORT F
			SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOC);
			SysCtlPeripheralEnable(SYSCTL_PERIPH_GPIOA);

	GPIOPinTypeGPIOOutput(GPIO_PORTC_BASE, GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7); //PC4 to PC7 are columns output

	GPIOPinTypeGPIOOutput(GPIO_PORTF_BASE, GPIO_PIN_1|GPIO_PIN_2|GPIO_PIN_3);//look to the comment below
	/*
	 * PF1 to PF3 can be used as a controlled pins of RELAY its also connected to RGB LEDs of TIVE C kit
	 * */

    GPIOPinWrite(GPIO_PORTC_BASE,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7,0xFF);//look to the comment below
    /*
     * GPIO_PORTC pin4 to pin 7 are connected to the columun pins of Keypad
     * they will sets to 1 and Keypad_wait fun. will clear its one by one in order leaving the others set to 1
     *
     * */

		GPIOPinTypeGPIOInput(GPIO_PORTA_BASE,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7);// look to the comment below
		/*
		 *GPIO PORTA pin4 to 7 are connected to the Rows pins of keypad
		 *they will set as input to perceive the sinyal that will come from Keypad
		 *
		 * */

		GPIOPadConfigSet(GPIO_PORTA_BASE, GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7, GPIO_STRENGTH_4MA, GPIO_PIN_TYPE_STD_WPU);// look to the comment below
		/*
		 * GPIO PORTA pin4 to 7 will sets to 1 and trigger to 1-0 fulling edge
		 * */

		GPIOIntRegister(GPIO_PORTA_BASE,KeyPad_int);//Register the Function of interrupting

		GPIOIntTypeSet(GPIO_PORTA_BASE,GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7,GPIO_FALLING_EDGE);//trigger to 1-0 fulling edge


		GPIOIntClear(GPIO_PORTA_BASE,  GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7);
		GPIOIntEnable(GPIO_PORTA_BASE,  GPIO_PIN_4|GPIO_PIN_5|GPIO_PIN_6|GPIO_PIN_7);
		IntEnable(INT_GPIOF_TM4C123);

}


