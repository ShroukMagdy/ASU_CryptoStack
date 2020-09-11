/*****************************************************************************
 *  File: HAS_Keypad_Password.h
 *  Copyright (C) 2018 ALHASAN ALKHATIB
 *
 *  date: June,2018
 *  Author: ALHASAN ALKHATIB
 *
 *  Description: Password security System To control a Relay
 *               using 16*16 Keypad and 16*2 LCD Display
 *               with ARM CORTEX -M4 TM4C123G Microprocessor (header file)
 *
 *****************************************************************************/

#ifndef HAS_KEYPAD_PASSWORD_H_
#define HAS_KEYPAD_PASSWORD_H_
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


/******************************************************************************************
*Function: Keypad_wait()
*
*Description: while the digits of password (the correct password or Enterd password )is lease than 4 digit
*             the operation of set-clear columns pins in order will countinues by using this function
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void KeyPad_wait();


/******************************************************************************************
*Function: Keypad_int()
*Description: the interrupting function of Keyoad_Seetup()
*             in this function operation of taking and proccesing the enterd charecter whill be perform
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void KeyPad_int();

/******************************************************************************************
*Function: Keypad_Setup()
*Description:this fun is used to Enable the pheriperal,preparing the Externel interreupting
*            and configing the input methods
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void KeyPad_Setup();

/******************************************************************************************
*Function:KeyPad_Lcd_Setup()
*Description:writing to LCD
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void KeyPad_Lcd_Setup();

/******************************************************************************************
*Function:KeyPad_PassWord_Confirm()
*Description:1-this function is used to Confirm the password if its correct or not
*              and according to that the Relay whill be sets to 1 or not
*            2-also used to confirm password resting
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
bool KeyPad_PassWord_Confirm();

/******************************************************************************************
*Function: NewPasswordWait()
*Description:to Clear the pin of Relay(or RGB RED) and'CorrectPasswordWait'
*            if the password is changed after Turning on the PIN(PF1)
*        	 Preparing LCD to New Password
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void NewPasswordWait();

/******************************************************************************************
*Function: PasswordTypeControl()
*Description:To determine the type of password if it's Enterd or New
*
*Parameteres:
*  void
*
*Return:
*  void
 *****************************************************************************************/
void PasswordTypeControl();

/******************************************************************************************
*Function: uint8_t power(uint8_t)
*Description:Calculate 2^x
*
*Parameteres:
*  uint8_t
*
*Return:
*  uint8_t
 *****************************************************************************************/
uint8_t power(uint8_t);

/******************************************************************************************
*Function: uint8_t ln(uint8_t)
*Description:Calculate log2(x)
*
*Parameteres:
*  uint8_t
*
*Return:
*  uint8_t
 *****************************************************************************************/
uint8_t ln(uint8_t);





#endif /* HAS_KEYPAD_PASSWORD_H_ */
