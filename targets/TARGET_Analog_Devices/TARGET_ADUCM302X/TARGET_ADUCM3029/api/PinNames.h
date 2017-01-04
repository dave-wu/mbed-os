/* mbed Microcontroller Library
 * Copyright (c) 2006-2013 ARM Limited
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef MBED_PINNAMES_H
#define MBED_PINNAMES_H

#include "cmsis.h"

#include "adi_gpio.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
    PIN_INPUT,
    PIN_OUTPUT
} PinDirection;

//update 

#define GPIO_PORT_SHIFT 12


typedef enum {
    P0_00  = (0 << GPIO_PORT_SHIFT | 0 ),
    P0_01  = (0 << GPIO_PORT_SHIFT | 1 ),
    P0_02  = (0 << GPIO_PORT_SHIFT | 2 ),
    P0_03  = (0 << GPIO_PORT_SHIFT | 3 ),
    P0_04  = (0 << GPIO_PORT_SHIFT | 4 ),
    P0_05  = (0 << GPIO_PORT_SHIFT | 5 ),
    P0_06  = (0 << GPIO_PORT_SHIFT | 6 ),
    P0_07  = (0 << GPIO_PORT_SHIFT | 7 ),
    P0_08  = (0 << GPIO_PORT_SHIFT | 8 ),
    P0_09  = (0 << GPIO_PORT_SHIFT | 9 ),
    P0_10 = (0 << GPIO_PORT_SHIFT | 10),
    P0_11 = (0 << GPIO_PORT_SHIFT | 11),
    P0_12 = (0 << GPIO_PORT_SHIFT | 12),
    P0_13 = (0 << GPIO_PORT_SHIFT | 13),
    P0_14 = (0 << GPIO_PORT_SHIFT | 14),
    P0_15 = (0 << GPIO_PORT_SHIFT | 15),
    P1_00  = (1 << GPIO_PORT_SHIFT | 0 ),
    P1_01  = (1 << GPIO_PORT_SHIFT | 1 ),
    P1_02  = (1 << GPIO_PORT_SHIFT | 2 ),
    P1_03  = (1 << GPIO_PORT_SHIFT | 3 ),
    P1_04  = (1 << GPIO_PORT_SHIFT | 4 ),
    P1_05  = (1 << GPIO_PORT_SHIFT | 5 ),
    P1_06  = (1 << GPIO_PORT_SHIFT | 6 ),
    P1_07  = (1 << GPIO_PORT_SHIFT | 7 ),
    P1_08  = (1 << GPIO_PORT_SHIFT | 8 ),
    P1_09  = (1 << GPIO_PORT_SHIFT | 9 ),
    P1_10 = (1 << GPIO_PORT_SHIFT | 10),
    P1_11 = (1 << GPIO_PORT_SHIFT | 11),
    P1_12 = (1 << GPIO_PORT_SHIFT | 12),
    P1_13 = (1 << GPIO_PORT_SHIFT | 13),
    P1_14 = (1 << GPIO_PORT_SHIFT | 14),
    P1_15 = (1 << GPIO_PORT_SHIFT | 15),
    P2_00  = (2 << GPIO_PORT_SHIFT | 0 ),
    P2_01  = (2 << GPIO_PORT_SHIFT | 1 ),
    P2_02  = (2 << GPIO_PORT_SHIFT | 2 ),
    P2_03  = (2 << GPIO_PORT_SHIFT | 3 ),
    P2_04  = (2 << GPIO_PORT_SHIFT | 4 ),
    P2_05  = (2 << GPIO_PORT_SHIFT | 5 ),
    P2_06  = (2 << GPIO_PORT_SHIFT | 6 ),
    P2_07  = (2 << GPIO_PORT_SHIFT | 7 ),
    P2_08  = (2 << GPIO_PORT_SHIFT | 8 ),
    P2_09  = (2 << GPIO_PORT_SHIFT | 9 ),
    P2_10 = (2 << GPIO_PORT_SHIFT | 10),
    P2_11 = (2 << GPIO_PORT_SHIFT | 11),
    P2_12 = (2 << GPIO_PORT_SHIFT | 12),
    P2_13 = (2 << GPIO_PORT_SHIFT | 13),
    P2_14 = (2 << GPIO_PORT_SHIFT | 14),
    P2_15 = (2 << GPIO_PORT_SHIFT | 15),

    // mbed original LED naming
    LED1 = P0_13,
    LED2 = P1_12,
    LED3 = P1_13,
    LED4 = P0_13,   //duplicate of led1
    LED5 = P1_12,   //duplicate of led2
    LED6 = P1_13,   //duplicate of led3

    //Push buttons
    PB0 = P1_14,
    PB1 = P2_06,
    BOOT = P1_01,
    WAKE_J12 = P0_15,  //4 options depending on jumper
    WAKE_J34 = P1_00,  //4 options depending on jumper
    WAKE_J56 = P0_13,  //4 options depending on jumper
    WAKE_J78 = P2_01,  //4 options depending on jumper
              
    // USB Pins
    USBTX = P0_10,
    USBRX = P0_11,

    // Arduino Headers
    D0 = P0_11,
    D1 = P0_10,
    D2 = P0_15,
    D3 = P2_11,
    D4 = P2_01,
    D5 = P2_02,
    D6 = P2_00,
    D7 = P0_12,
    D8 = P1_02,
    D9 = P1_15,
    D10 = P0_03,
    D11 = P0_01,
    D12 = P0_02,
    D13 = P0_00,
    D14 = P0_05,
    D15 = P0_04,
    
    I2C_SCL = D15,
    I2C_SDA = D14,

//    A0 = ADC0,
//    A1 = ADC1,
//    A2 = ADC2,
//    A3 = ADC3,
//    A4 = ADC4,
//    A5 = ADC5,

    // Not connected
    NC = (int)0xFFFFFFFF
} PinName;


typedef enum {
    PullNone = 0,
    PullDown = 1,
    PullUp   = 2,
    PullDefault = PullNone
} PinMode;

#ifdef __cplusplus
}
#endif

#endif
