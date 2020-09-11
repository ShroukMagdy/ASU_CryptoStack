/*
 * uart.h
 *
 *  Created on: Jun 18, 2020
 */

#ifndef TEST_UART_H_
#define TEST_UART_H_

 #include "Platform_Types.h"

#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include "inc/hw_memmap.h"
#include "inc/hw_types.h"
#include "driverlib/gpio.h"
#include "driverlib/pin_map.h"
#include "driverlib/sysctl.h"
#include "driverlib/uart.h"

void uart_init();
void uart_send(uint8 result[],uint32 result_length );
void uart_recieve(uint8 result[],uint32 result_length);

#endif /* UART_H_ */
