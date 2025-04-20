// EMV-Tools_Win.cpp : This file contains the 'main' function. Program execution begins and ends there.
//
#include <winscard.h>
#include <iostream>
#include "scard_common.h"
#include "apdu.h"




#ifdef __cplusplus
extern "C" {
#endif

    int main()
    {
        std::cout << "Hello World!\n";
    }

    void InitOmnikey() {
        SCardContext* ctx = scard_establish(SCARD_SCOPE_SYSTEM);
        scard_connect(ctx, "OMNIKEY CardMan 5x21 0", SCARD_SHARE_EXCLUSIVE);
        scard_omnikey_set_led(ctx, OMNIKEY_LED_GREEN); 
    }


#ifdef MANUAL_MODE
    void manual_feed_response(const uint8_t* rsp, size_t len) {
        // Store for next transmit()
    }
#endif

    const uint8_t AIDs[][16] = {
    { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10 }, // Visa Credit
    { 0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10 }, // Visa Electron
    { 0xA0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10 }, // Mastercard Credit/debit
    { 0xA0, 0x00, 0x00, 0x00, 0x65, 0x10, 0x10 }, // JCB
    { 0xA0, 0x00, 0x00, 0x25, 0x01, 0x08, 0x01 }, // American Express
    { 0xA0, 0x00, 0x00, 0x01, 0x52, 0x30, 0x10 }, // Discover
    { 0xA0, 0x00, 0x03, 0x33, 0x01, 0x01, 0x01 }, // Unionpay
    };




    // Run program: Ctrl + F5 or Debug > Start Without Debugging menu
    // Debug program: F5 or Debug > Start Debugging menu

    // Tips for Getting Started: 
    //   1. Use the Solution Explorer window to add/manage files
    //   2. Use the Team Explorer window to connect to source control
    //   3. Use the Output window to see build output and other messages
    //   4. Use the Error List window to view errors
    //   5. Go to Project > Add New Item to create new code files, or Project > Add Existing Item to add existing code files to the project
    //   6. In the future, to open this project again, go to File > Open > Project and select the .sln file

#ifdef __cplusplus
}
#endif
