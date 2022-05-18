#include "LittleFS.h"
#include "AESLib.h"
//#include <ESP32Time.h>

#include <ESP8266WiFi.h>
#include <ESP8266WebServer.h>
#include <ESP8266HTTPClient.h>


AESLib aesLib;
String plaintext = "HELLOWORLD";
char ssidbuff[20] = {0};
char passwordbuff[30] = {0};
char passwordbuff2[8] = {0};
// AES Encryption Key
byte aes_key[] = { 0xBD, 0x17, 0xBB, 0x34, 0xBB, 0x22, 0x12, 0x6F, 0xE8, 0x88, 0xFF, 0x99, 0xA1, 0xDA, 0x17, 0xF4 };
// General initialization vector (you must use your own IV's in production for full security!!!)
byte aes_iv[N_BLOCK] = { 0xAF, 0xBC, 0xDA, 0xEE, 0x89, 0x78, 0x77, 0x67, 0x76, 0x56, 0x45, 0x35, 0x12, 0x28, 0xAE, 0x0A };

ESP8266WebServer server(80);

#define LENGTH                       0x00
#define AARQ_APPCONTEXT              0xA1
#define AARQ_ACSE_REQS               0x8A
#define AARQ_ACSE_REQ_LEN            0x02
#define AARQ_AUTHMECHNAME            0x8B
#define AARQ_AUTHVALUE               0xAC
#define AARQ_USER_INFO               0xBE
#define TAG_GET_REQ_NORMAL           0x01
#define AARQ_XDLMS_DEDICATED_KEY     0x00
#define AARQ_XDLMS_RESPONSE_ALLOWED  0x00
#define AARQ_XDLMS_QOS               0x00
#define DLMS_VERSION                 0x06
#define AARQ_CONFORMANCE             0x5F
#define AARQ_CONFORMANCE_OLD         0x1F
#define ENCRYPTION_ONLY              0x20
#define DT_ARRAY                     1
#define DT_STRUCTURE                 2
#define DT_LONG_UNSIGNED             18
#define DT_OCTET_STRING              9
#define DT_INTEGER                   15
#define SECURE                       0
#define LG                           1
#define LT                           2
#define HPL                          3
#define GENUS                        4
#define CAP                          5
#define MAXWELL                      6
#define SINGLE_PH_PARAM_COUNT        17
#define THREE_PH_PARAM_COUNT         27
#define ASSC_REQ_COUNT               3
#define MAX_SIZE                     115
#define MAX_SIZE_RESPONSE_BUFFER     256
#define METER_RTC_READ_REQ_COUNT     1
char Hdlc_OutBuf[255] = {0};
int fcstab[] = {
  0x0000, 0x1189, 0x2312, 0x329b, 0x4624, 0x57ad, 0x6536, 0x74bf,
  0x8c48, 0x9dc1, 0xaf5a, 0xbed3, 0xca6c, 0xdbe5, 0xe97e, 0xf8f7,
  0x1081, 0x0108, 0x3393, 0x221a, 0x56a5, 0x472c, 0x75b7, 0x643e,
  0x9cc9, 0x8d40, 0xbfdb, 0xae52, 0xdaed, 0xcb64, 0xf9ff, 0xe876,
  0x2102, 0x308b, 0x0210, 0x1399, 0x6726, 0x76af, 0x4434, 0x55bd,
  0xad4a, 0xbcc3, 0x8e58, 0x9fd1, 0xeb6e, 0xfae7, 0xc87c, 0xd9f5,
  0x3183, 0x200a, 0x1291, 0x0318, 0x77a7, 0x662e, 0x54b5, 0x453c,
  0xbdcb, 0xac42, 0x9ed9, 0x8f50, 0xfbef, 0xea66, 0xd8fd, 0xc974,
  0x4204, 0x538d, 0x6116, 0x709f, 0x0420, 0x15a9, 0x2732, 0x36bb,
  0xce4c, 0xdfc5, 0xed5e, 0xfcd7, 0x8868, 0x99e1, 0xab7a, 0xbaf3,
  0x5285, 0x430c, 0x7197, 0x601e, 0x14a1, 0x0528, 0x37b3, 0x263a,
  0xdecd, 0xcf44, 0xfddf, 0xec56, 0x98e9, 0x8960, 0xbbfb, 0xaa72,
  0x6306, 0x728f, 0x4014, 0x519d, 0x2522, 0x34ab, 0x0630, 0x17b9,
  0xef4e, 0xfec7, 0xcc5c, 0xddd5, 0xa96a, 0xb8e3, 0x8a78, 0x9bf1,
  0x7387, 0x620e, 0x5095, 0x411c, 0x35a3, 0x242a, 0x16b1, 0x0738,
  0xffcf, 0xee46, 0xdcdd, 0xcd54, 0xb9eb, 0xa862, 0x9af9, 0x8b70,
  0x8408, 0x9581, 0xa71a, 0xb693, 0xc22c, 0xd3a5, 0xe13e, 0xf0b7,
  0x0840, 0x19c9, 0x2b52, 0x3adb, 0x4e64, 0x5fed, 0x6d76, 0x7cff,
  0x9489, 0x8500, 0xb79b, 0xa612, 0xd2ad, 0xc324, 0xf1bf, 0xe036,
  0x18c1, 0x0948, 0x3bd3, 0x2a5a, 0x5ee5, 0x4f6c, 0x7df7, 0x6c7e,
  0xa50a, 0xb483, 0x8618, 0x9791, 0xe32e, 0xf2a7, 0xc03c, 0xd1b5,
  0x2942, 0x38cb, 0x0a50, 0x1bd9, 0x6f66, 0x7eef, 0x4c74, 0x5dfd,
  0xb58b, 0xa402, 0x9699, 0x8710, 0xf3af, 0xe226, 0xd0bd, 0xc134,
  0x39c3, 0x284a, 0x1ad1, 0x0b58, 0x7fe7, 0x6e6e, 0x5cf5, 0x4d7c,
  0xc60c, 0xd785, 0xe51e, 0xf497, 0x8028, 0x91a1, 0xa33a, 0xb2b3,
  0x4a44, 0x5bcd, 0x6956, 0x78df, 0x0c60, 0x1de9, 0x2f72, 0x3efb,
  0xd68d, 0xc704, 0xf59f, 0xe416, 0x90a9, 0x8120, 0xb3bb, 0xa232,
  0x5ac5, 0x4b4c, 0x79d7, 0x685e, 0x1ce1, 0x0d68, 0x3ff3, 0x2e7a,
  0xe70e, 0xf687, 0xc41c, 0xd595, 0xa12a, 0xb0a3, 0x8238, 0x93b1,
  0x6b46, 0x7acf, 0x4854, 0x59dd, 0x2d62, 0x3ceb, 0x0e70, 0x1ff9,
  0xf78f, 0xe606, 0xd49d, 0xc514, 0xb1ab, 0xa022, 0x92b9, 0x8330,
  0x7bc7, 0x6a4e, 0x58d5, 0x495c, 0x3de3, 0x2c6a, 0x1ef1, 0x0f78
};
enum Frametypes
{
  INFORMATION_FRAME,
  SUPERVISORY_FRAME,
  SNRM_FRAME,
  DISCONNECT_FRAME
};
char Fromdate[6] = {0};
char Todate[6] = {0};
char arrqframe_index = 0;
//char passwordkey[]={0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31};//HPL
//char passwordkey[]={0x6D, 0x78, 0x32, 0x30, 0x31, 0x31, 0x39, 0x39};//MAXWELL
//char passwordkey[]={0x6C,0x6E,0x74,0x31};//L&T
//char passwordkey[]={0X41, 0X42, 0X43, 0X44, 0X30, 0X30, 0X30, 0X31};//SECURE
char TAG_AARQ =   0x60;
char AARQFrame[128] = {0};
char  app_ctxt_name_1[] =  { AARQ_APPCONTEXT, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x01 };
char aARQ_aCSE_rEQs[] = {AARQ_ACSE_REQS, AARQ_ACSE_REQ_LEN, 0x07, 0x80};
char auth_mech_name_1[] = { AARQ_AUTHMECHNAME, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01 };
//char password_tag []= { AARQ_AUTHVALUE, 0x02 + 0x10, 0x80, 0x10 };//HPL
//char password_tag []= { AARQ_AUTHVALUE, 0x02 + 0x08, 0x80, 0x08 };//MAXWELL & SECURE
//char password_tag []= { AARQ_AUTHVALUE, 0x02 + 0x04, 0x80, 0x04 };//L&T

int buildid = 1;

String LLS_Keys[] = {"ABCD0001",
                     "11111111",
                     "lnt1",
                     "1111111111111111",
                     "1A2B3C4D",
                     "123456",
                     "mx201199"
                      };

char auth_password_or_public_Tag_len[] =  { AARQ_USER_INFO, 0x02 + 0x0E, 0x04, 0x0E };
char xDlmsRequest1[]={TAG_GET_REQ_NORMAL, AARQ_XDLMS_DEDICATED_KEY, AARQ_XDLMS_RESPONSE_ALLOWED, AARQ_XDLMS_QOS, DLMS_VERSION, AARQ_CONFORMANCE, AARQ_CONFORMANCE_OLD, 0x04, 0x00, 0x00, 0x1E, 0x1D, 0xFF, 0xFF};
char Obiscode1[] = {0x07, 0x01 ,0x00, 94, 0x5B, 0x04, 0xFF, 0x03,0x00};
char Obiscode2[] = {0x07, 0x01 ,0x00, 94, 0x5B, 0x04, 0xFF, 0x02,0x00};
char Obiscode3[] = {0x07, 0x01 ,0x00, 99, 0x01, 0x00, 0xFF, 0x03,0x00};
char Obiscode4[] = {0x07, 0x01 ,0x00, 99, 0x01, 0x00, 0xFF, 0x02,0x00};
char * Obiscode[] =
{
  Obiscode1,
  Obiscode2,
  Obiscode3,
  Obiscode4
};
char ObiscodeIndex = 0;
char TAG_GET_REQ   = 0xC0;
char REQ_GET_NORMAL= 1;
char unciperIframe[128] = {0};
char STRUCT_LENGTH = 0x04;
char HDLC_Logical_Name = 0x00;

#if 0
char DLMS_SNRM[] ={0x09,0x7E,0xA0,0x07,0x03,0x41,0x93,0x5A,0x64,0x7E,'\0'};
char DLMS_LLS_Capital[] ={0x48,0x7E,0xA0,0x46,0x03,0x41,0x10,0xC5,0xD8,0xE6,0xE6,0x00,0x60,0x38,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x08,0x80,0x06,0x31,0x32,0x33,0x34,0x35,0x36,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x42,0x5F,0x7E,'\0'};
char DLMS_LLS_LT[] ={0x46,0x7E,0xA0,0x44,0x03,0x41,0x10,0xB3,0xE1,0xE6,0xE6,0x00,0x60,0x36,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x06,0x80,0x04,0x6C,0x6E,0x74,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x1F,0x5E,0x7E,'\0'};
char DLMS_LLS_HPL[] ={0x52,0x7E,0xA0,0x50,0x03,0x41,0x10,0xFE,0x50,0xE6,0xE6,0x00,0x60,0x42,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x12,0x80,0x10,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0xA5,0xED,0x7E,'\0'};
char DLMS_LLS_LG[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x43,0x8A,0x7E,'\0'};
char DLMS_LLS_SECURE[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x41,0x42,0x43,0x44,0x30,0x30,0x30,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x8A,0xC8,0x7E,'\0'};
char DLMS_LLS_GENUS[] ={0x59, 0x7E, 0xA0, 0x57, 0x03, 0x41, 0x10, 0xDF, 0x07, 0xE6, 0xE6, 0x00, 0x60, 0x49, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x03, 0xA6, 0x0A, 0x04, 0x08, 0x47, 0x4F, 0x45, 0x30, 0x30, 0x30, 0x30, 0x30, 0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01, 0xAC, 0x0A, 0x80, 0x08, 0x31, 0x41, 0x32, 0x42, 0x33, 0x43, 0x34, 0x44, 0xBE, 0x17, 0x04, 0x15, 0x21, 0x13, 0x20, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x0A, 0x82, 0xD1, 0x8E, 0x20, 0x47, 0xAB, 0xBD, 0xDB, 0xE9, 0xE2, 0x7C, 0x8B, 0xE9, 0xBE, 0x7E,'\0'};
char DLMS_LLS_MAXWELL[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x6D,0x78,0x32,0x30,0x31,0x31,0x39,0x39,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x1E,0x1D,0xFF,0xFF,0x3F,0xE1,0x7E,'\0'};//MAXWELL 04-04-2022
char DLMSCommand_END[] ={0x09,0x7E,0xA0,0x07,0x03,0x41,0x53,0x56,0xA2,0x7E,'\0'};
char DLMSCommand_MeterType[]={0x1B,0x7E,0xA0,0x19,0x03,0x41,0x32,0x3A,0xBD,0xE6,0xE6,0x00,0xC0,0x01,0xC1,0x00,0x01,0x00,0x00,0x5E,0x5B,0x09,0xFF,0x02,0x00,0x52,0x9E,0x7E,'\0'};
#endif

//char REQframeptr[7][MAX_SIZE];
//char ADMTreqptr[4][MAX_SIZE];
int incomingByte = 0;
char g_RRR=0;
char g_SSS=0;
char INST_Obiscode1[] = {0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x02};/*RTC*/
char INST_Obiscode2[] = {0x03, 0x01, 0x00, 0x0C, 0x07, 0x00, 0xFF, 0x02};/*VTG*/
char INST_Obiscode3[] = {0x03, 0x01, 0x00, 0x0B, 0x07, 0x00, 0xFF, 0x02};/*PhAmp*/
char INST_Obiscode4[] = {0x03, 0x01, 0x00, 0x5B, 0x07, 0x00, 0xFF, 0x02};/*NuAmp*/
char INST_Obiscode5[] = {0x03, 0x01, 0x00, 0x0D, 0x07, 0x00, 0xFF, 0x02};/*PF*/
char INST_Obiscode6[] = {0x03, 0x01, 0x00, 0x0E, 0x07, 0x00, 0xFF, 0x02};/*Freq*/
char INST_Obiscode7[] = {0x03, 0x01, 0x00, 0x09, 0x07, 0x00, 0xFF, 0x02};/*kVA*/
char INST_Obiscode8[] = {0x03, 0x01, 0x00, 0x01, 0x07, 0x00, 0xFF, 0x02};/*kW*/
char INST_Obiscode9[] = {0x03, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, 0x02};/*kWh*/
char INST_Obiscode10[] = {0x03, 0x01, 0x00, 0x09, 0x08, 0x00, 0xFF, 0x02};/*kVAh*/
char INST_Obiscode11[] = {0x04, 0x01, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x02};/*MDkW*/
char INST_Obiscode12[] = {0x04, 0x01, 0x00, 0x09, 0x06, 0x00, 0xFF, 0x02};/*MDkVA*/
char INST_Obiscode13[] = {0x03, 0x00, 0x00, 0x5E, 0x5B, 0x0E, 0xFF, 0x02};/*PowONPowON*/
char INST_Obiscode14[] = {0x01, 0x00, 0x00, 0x5E, 0x5B, 0x00, 0xFF, 0x02};/*TamCt*/
char INST_Obiscode15[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF, 0x02};/*BilCt*/
char INST_Obiscode16[] = {0x01, 0x00, 0x00, 0x60, 0x02, 0x00, 0xFF, 0x02};/*PgmCt*/
char INST_Obiscode17[] = {0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0xFF, 0x02};/*MSN*///30-03-2022
char * INST_Obiscode[] =
{
  INST_Obiscode1,
  INST_Obiscode2,
  INST_Obiscode3,
  INST_Obiscode4,
  INST_Obiscode5,
  INST_Obiscode6,
  INST_Obiscode7,
  INST_Obiscode8,
  INST_Obiscode9,
  INST_Obiscode10,
  INST_Obiscode11,
  INST_Obiscode12,
  INST_Obiscode13,
  INST_Obiscode14,
  INST_Obiscode15,
  INST_Obiscode16,
  INST_Obiscode17//30-03-2022
};

//14-04-2022
//char INST_Obiscode1_Scalar[] = {0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x03};/*RTC*/
//char INST_Obiscode2_Scalar[] = {0x03, 0x01, 0x00, 0x0C, 0x07, 0x00, 0xFF, 0x03};/*VTG*/
//char INST_Obiscode3_Scalar[] = {0x03, 0x01, 0x00, 0x0B, 0x07, 0x00, 0xFF, 0x03};/*PhAmp*/
//char INST_Obiscode4_Scalar[] = {0x03, 0x01, 0x00, 0x5B, 0x07, 0x00, 0xFF, 0x03};/*NuAmp*/
//char INST_Obiscode5_Scalar[] = {0x03, 0x01, 0x00, 0x0D, 0x07, 0x00, 0xFF, 0x03};/*PF*/
//char INST_Obiscode6_Scalar[] = {0x03, 0x01, 0x00, 0x0E, 0x07, 0x00, 0xFF, 0x03};/*Freq*/
//char INST_Obiscode7_Scalar[] = {0x03, 0x01, 0x00, 0x09, 0x07, 0x00, 0xFF, 0x03};/*kVA*/
//char INST_Obiscode8_Scalar[] = {0x03, 0x01, 0x00, 0x01, 0x07, 0x00, 0xFF, 0x03};/*kW*/
//char INST_Obiscode9_Scalar[] = {0x03, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, 0x03};/*kWh*/
//char INST_Obiscode10_Scalar[] = {0x03, 0x01, 0x00, 0x09, 0x08, 0x00, 0xFF, 0x03};/*kVAh*/
//char INST_Obiscode11_Scalar[] = {0x04, 0x01, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x03};/*MDkW*/
//char INST_Obiscode12_Scalar[] = {0x04, 0x01, 0x00, 0x09, 0x06, 0x00, 0xFF, 0x03};/*MDkVA*/
//char INST_Obiscode13_Scalar[] = {0x03, 0x00, 0x00, 0x5E, 0x5B, 0x0E, 0xFF, 0x03};/*PowONPowON*/
//char INST_Obiscode14_Scalar[] = {0x01, 0x00, 0x00, 0x5E, 0x5B, 0x00, 0xFF, 0x03};/*TamCt*/
//char INST_Obiscode15_Scalar[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF, 0x03};/*BilCt*/
//char INST_Obiscode16_Scalar[] = {0x01, 0x00, 0x00, 0x60, 0x02, 0x00, 0xFF, 0x03};/*PgmCt*/
//char INST_Obiscode17_Scalar[] = {0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0xFF, 0x03};/*MSN*///30-03-2022
//
//char * INST_Obiscode_Scalar[] =
//{
//  INST_Obiscode1_Scalar,
//  INST_Obiscode2_Scalar,
//  INST_Obiscode3_Scalar,
//  INST_Obiscode4_Scalar,
//  INST_Obiscode5_Scalar,
//  INST_Obiscode6_Scalar,
//  INST_Obiscode7_Scalar,
//  INST_Obiscode8_Scalar,
//  INST_Obiscode9_Scalar,
//  INST_Obiscode10_Scalar,
//  INST_Obiscode11_Scalar,
//  INST_Obiscode12_Scalar,
//  INST_Obiscode13_Scalar,
//  INST_Obiscode14_Scalar,
//  INST_Obiscode15_Scalar,
//  INST_Obiscode16_Scalar,
//  INST_Obiscode17_Scalar//30-03-2022
//};
bool Get_Scalar_Flag = false;
//14-04-2022

enum MeterDataTypes
{
  INSTANTANEOUS_DATA,
  LOAD_PROFILE_DATA
};
//char INST_REQframeptr[SINGLE_PH_PARAM_COUNT + ASSC_REQ_COUNT][255];
//char INST_3PH_REQframeptr[THREE_PH_PARAM_COUNT + ASSC_REQ_COUNT][255];
int PhaseType = 0;
enum PhaseTypes
{
  SINGLE_PHASE = 1,
  THREE_PHASE = 3
};
char THREE_PH_INST_Obiscode1[] = {0x08, 0x00, 0x00, 0x01, 0x00, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode2[] = {0x03, 0x01, 0x00, 0x1F, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode3[] = {0x03, 0x01, 0x00, 0x33, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode4[] = {0x03, 0x01, 0x00, 0x47, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode5[] = {0x03, 0x01, 0x00, 0x20, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode6[] = {0x03, 0x01, 0x00, 0x34, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode7[] = {0x03, 0x01, 0x00, 0x48, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode8[] = {0x03, 0x01, 0x00, 0x21, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode9[] = {0x03, 0x01, 0x00, 0x35, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode10[] = {0x03, 0x01, 0x00, 0x49, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode11[] = {0x03, 0x01, 0x00, 0x0D, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode12[] = {0x03, 0x01, 0x00, 0x0E, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode13[] = {0x03, 0x01, 0x00, 0x09, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode14[] = {0x03, 0x01, 0x00, 0x01, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode15[] = {0x03, 0x01, 0x00, 0x03, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode16[] = {0x03, 0x01, 0x00, 0x01, 0x08, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode17[] = {0x03, 0x01, 0x00, 0x05, 0x08, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode18[] = {0x03, 0x01, 0x00, 0x08, 0x08, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode19[] = {0x03, 0x01, 0x00, 0x09, 0x08, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode20[] = {0x01, 0x00, 0x00, 0x60, 0x07, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode21[] = {0x03, 0x00, 0x00, 0x5E, 0x5B, 0x08, 0xFF, 0x02};
char THREE_PH_INST_Obiscode22[] = {0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode23[] = {0x01, 0x00, 0x00, 0x60, 0x02, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode24[] = {0x03, 0x00, 0x00, 0x00, 0x01, 0x02, 0xFF, 0x02};
char THREE_PH_INST_Obiscode25[] = {0x04, 0x01, 0x00, 0x01, 0x06, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode26[] = {0x04, 0x01, 0x00, 0x09, 0x06, 0x00, 0xFF, 0x02};
char THREE_PH_INST_Obiscode27[] = {0x01, 0x00, 0x00, 0x60, 0x01, 0x00, 0xFF, 0x02};/*MSN*///30-03-2022
char * THREE_PH_INST_Obiscode[] =
{
  THREE_PH_INST_Obiscode1,
  THREE_PH_INST_Obiscode2,
  THREE_PH_INST_Obiscode3,
  THREE_PH_INST_Obiscode4,
  THREE_PH_INST_Obiscode5,
  THREE_PH_INST_Obiscode6,
  THREE_PH_INST_Obiscode7,
  THREE_PH_INST_Obiscode8,
  THREE_PH_INST_Obiscode9,
  THREE_PH_INST_Obiscode10,
  THREE_PH_INST_Obiscode11,
  THREE_PH_INST_Obiscode12,
  THREE_PH_INST_Obiscode13,
  THREE_PH_INST_Obiscode14,
  THREE_PH_INST_Obiscode15,
  THREE_PH_INST_Obiscode16,
  THREE_PH_INST_Obiscode17,
  THREE_PH_INST_Obiscode18,
  THREE_PH_INST_Obiscode19,
  THREE_PH_INST_Obiscode20,
  THREE_PH_INST_Obiscode21,
  THREE_PH_INST_Obiscode22,
  THREE_PH_INST_Obiscode23,
  THREE_PH_INST_Obiscode24,
  THREE_PH_INST_Obiscode25,
  THREE_PH_INST_Obiscode26,
  THREE_PH_INST_Obiscode27
};
//char Meter_RTC_REQframeptr[4][MAX_SIZE];
char ResponseBuffer[35][MAX_SIZE_RESPONSE_BUFFER] = {0};
//ESP32Time rtc;
int MeterCategoryType = 0;
//char FileBuffer[31][MAX_SIZE];
char Chopped_Inst_DataBuffer[256] = {0};
char Chopped_Inst_Scalar_DataBuffer[256] = {0};//14-04-2022
char Chopped_Load_DataBuffer[512] = {0};
//char Combined_DataBuffer[1024];


long ParsedMeterSerialNo = 0;//30-03-2022
String MeterSerialNo_Final = "";//30-03-2022

String BlockIDs[] = {"00|00", "00|01", "00|02", "00|03", "00|04", "00|05", "00|06", "00|07", "00|08", "00|09", "00|10", "00|11", "00|12",
                     "00|13", "00|14", "00|15", "00|16", "00|17", "00|18", "00|19", "00|20", "00|21", "00|22", "00|23"};//30-03-2022
String BlockIDs_Buffer[24] = {"0"};//30-03-2022
//String BlockIDsFileName = "";//30-03-2022
char temp_Char_Array[4] = {0};//04-04-2022

/*SOFTWARE RTC RELATED VALRIABLES*/
long timeNow = 0;
long timeLast = 0;

//Time start Settings:
int startingHour = 0; // set your starting hour here, not below at int hour. This ensures accurate daily correction of time
int seconds = 0;
int ActualSeconds = 0;
int minutes = 0;
int hours = 0;
int days = 0;
int day = 0;
int month = 0;
int year = 0;

//Accuracy settings
int dailyErrorFast = 0; // set the average number of milliseconds your microcontroller's time is fast on a daily basis
int dailyErrorBehind = 0; // set the average number of milliseconds your microcontroller's time is behind on a daily basis

int correctedToday = 1; // do not change this variable, one means that the time has already been corrected today for the error in your boards crystal. This is true for the first day because you just set the time when you uploaded the sketch.  
/*SOFTWARE RTC RELATED VALRIABLES*/

bool reset_flag = false;
int METER_MAKE = 0;




//relay operation variables
uint8_t GPIO_Pin = 2;
uint8_t RELAY_ON = 12 ;
uint8_t RELAY_OFF = 13 ;

int CYCLE_TIME_IN_MINS = 59;

int resume_reading = 0;
int is_reading_interrupted = 0;

String global_NodeID = "";



void setup()
{
  Serial.begin(115200);

String suffix = "NSTG0000";
String gwid ="";

for(int i =99;i < 100;i++)
{

gwid = suffix + String(i);

char a[11];
gwid.toCharArray(a,11);
String passwd = password_generator(a);

Serial.println(gwid + "   password:" + passwd);

}



}

void setup2()
{
  //Serial.begin(115200);
  Serial.begin(9600);
  //delay(2000);


  pinMode(RELAY_ON, OUTPUT);
  pinMode(RELAY_OFF, OUTPUT);

  
  /*****************************************/
  if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    return;
  }

  String ssid_node = node_serialization(buildid);



  //CheckForNodeID();
  Serial.println("Node ID: " + global_NodeID);
  global_NodeID.trim();

  int n = global_NodeID.length();
  char temp_global_NodeID[n + 1] = {0};
  strcpy(temp_global_NodeID, global_NodeID.c_str());
  /*for (int i = 0; i < n; i++)
    Serial.print((String)temp_global_NodeID[i]);
  Serial.println();*/
    
  String password_aes = password_generator(temp_global_NodeID);
  //Serial.println("GENERATED PWD: " + password_aes);
  
  WiFi.softAP( global_NodeID, password_aes);
  IPAddress myIP = WiFi.softAPIP();

  WiFi.setOutputPower(13);
  //Serial.print("\r\nAP IP address: ");
  //Serial.print(myIP);
  //Serial.print("\r\n\r\n");
  server.on("/getlogs", handlelogs);
  server.on("/getfilelist", handlefilelist);
  server.on("/getfiledata", handlefiledata);

  server.on("/deletemeterdata",handledeletemeterdata);
  server.on("/getfiledata", handlefiledata);
  
  server.on("/deletefile",handledeletefile);

  server.on("/relayoperation",handlerelayop);  

  server.on("/resumereading",handleresumereading); 

  server.on("/getmeterslno",handlemeterslno); 

  server.on("/getrelaystatus",handlerelaystatus); 
  
 
  server.begin();
  /*****************************************/ 
  
  //Checking for available File Storage Memory in ESP Before Starting Meter Reading Tasks
  CheckLogFileSize();
  CheckMeterDataFilesSize();

  //seriallogger_string((String)(sizeof(LLS_Keys) / sizeof(LLS_Keys[0])));

  seriallogger_string("****************START*****************");
  int meter_index = 0;
  //seriallogger_string("*************");
  while(meter_index < (sizeof(LLS_Keys) / sizeof(LLS_Keys[0])))
  {
    //seriallogger_string((String)meter_index);
    if(AutoDetectMeterType(meter_index))
      break;
    
    meter_index++;
    //seriallogger_string((String)meter_index);
  }
  //seriallogger_string("*************");
  //METER_MAKE = meter_index;
  seriallogger_string("METER MAKE ID: " + (String)METER_MAKE);
  //InitialiseESP32RTC();
  
  if(METER_MAKE < (sizeof(LLS_Keys) / sizeof(LLS_Keys[0])))     
  {
    /***********************************************************************************************************************SYCN RTC FROM METER START*/
    //Serial.println();                                   //seriallogger_string("\r\n");
    //Serial.println("Init RTC...");                      
    //seriallogger_string("Init RTC...");
    //Serial.println();                                   //seriallogger_string("\r\n");


    //delay(10000);
    if(InitialiseESP32RTC(/*Meter_RTC_REQframeptr*/))
    {
        //Serial.println("Init RTC Completed.");              
        //seriallogger_string("Init RTC Completed.");
        //Serial.println();
        /************************************************************************************************************************SYCN RTC FROM METER END*/
      
        /***********************************************************************************************************************AUTO DETECT METER TYPE START*/
        //Serial.println();                                                                           //seriallogger_string("\r\n");
        //Serial.println("Detecting Meter Category Type...");                                         //seriallogger_string("Detecting Meter Category Type...\r\n");
        //Serial.println();  
        //seriallogger_string("\r\n");
  
        
        //AutoDetectMeterType(2/*,ADMTreqptr*/);//3 for HPL //6 for MAXWELL //2 for L&T //0 for SECURE
        //Serial.println("Detecting Meter Category Type Completed.");                                 seriallogger_string("Detecting Meter Category Type Completed.");
        //Serial.println();                                                                           //seriallogger_string("\r\n");
        /***********************************************************************************************************************AUTO DETECT METER TYPE END*/
      
        /*INITIALIZING BLOCK ID FILE NAME*///30-03-2022
        String BlockIDsFileName = "";//19-04-2022
        BlockIDsFileName = "/BlockIDStatusFiles";
        BlockIDsFileName += "/";
        BlockIDsFileName += (String)day;//(String)rtc.getDay();  
        BlockIDsFileName += "-";
        BlockIDsFileName += (String)month/*(rtc.getMonth()+1)*/;
        BlockIDsFileName += "-";
        BlockIDsFileName += (String)year/*rtc.getYear()*/;
        BlockIDsFileName += ".txt";

        seriallogger_string(BlockIDsFileName);
       
        /*if (!LittleFS.begin()) {
        //Serial.println("An Error has occurred while mounting LittleFS");
        seriallogger_string("An Error has occurred while mounting LittleFS");
        return;
        }*/
                                                                                            //LittleFS.remove(BlockIDsFileName);          //TO BE REMOVED
        CreateBlockIDFIle(BlockIDsFileName);//19-04-2022
        /*INITIALIZING BLOCK ID FILE NAME*/

        if(!CheckForInstDataStatus())
        {
          delay(2000);
          ReadInstData();//Reading Instantaneous Profile Data At Start Up
        }
        else
        {
          MeterSerialNo_Final = "";
          MeterSerialNo_Final = ReadMSNFromFile("/MeterSlNo/MSN.txt");
          MeterSerialNo_Final.trim();
        }
        //ReadLoadProfileData(hours, minutes/*rtc.getMinute()*/, day/*rtc.getDay()*/, month/*rtc.getMonth()*/, year/*rtc.getYear()*/);//04-04-2022
        //UpdateBlockID();    
        
        if(MeterSerialNo_Final.length() != 0)//IF METER SERIAL NUMBER IS NOT AVAILABLE DONT PROCEED FURTHER
        {
          delay(2000);
          //seriallogger_string("READING MISSING LOAD PROFILE BLOCKS OF CURRENT DAY");
          ReadMissingLoadProfileBlock();
          //Serial.println("\r\nCOMPLETED READING MISSING LOAD PROFILE BLOCKS\r\n");
          //seriallogger_string("COMPLETED READING MISSING LOAD PROFILE BLOCKS OF CURRENT DAY");
        }    
   
        /*READ MISSING LOAD PROFILE BLOCKS OF PREVIOUS REQUESTED DAY 19-04-2022*/
      
         //Obtain Date of the day for which load profile data has to be read
      
        /*String temp_date = "/BlockIDStatusFiles";
        temp_date += "/";
        temp_date += "17-4-2022";
        temp_date += ".txt";  
        CreateBlockIDFIle(temp_date);//19-04-2022*/
   #if 0
        String temp_date = "";
        temp_date = "/BlockIDStatusFiles";
        temp_date += "/";
        temp_date += "18-4-2022";
        temp_date += ".txt";  
        CreateBlockIDFIle(temp_date);//19-04-2022
      
      
        temp_date = "";
        temp_date = "/BlockIDStatusFiles";
        temp_date += "/";
        temp_date += "19-4-2022";
        temp_date += ".txt";  
        CreateBlockIDFIle(temp_date);//19-04-2022
  
        temp_date = "";
        temp_date = "/BlockIDStatusFiles";
        temp_date += "/";
        temp_date += "20-4-2022";
        temp_date += ".txt";  
        CreateBlockIDFIle(temp_date);//19-04-2022
   #endif
        
        /*READ MISSING LOAD PROFILE BLOCKS OF PREVIOUS REQUESTED DAY 19-04-2022*/      
        if(!InitialiseESP32RTC())
        {
          Set_Default_RTC();
          seriallogger_string("DATE TIME SYNC FAILED");
        }
        seriallogger_string("****************END*****************");
    }
    else
    {
      CYCLE_TIME_IN_MINS = 1;
      Set_Default_RTC();
      seriallogger_string("DATE TIME SYNC FAILED");
      seriallogger_string("****************END*****************");
    }
  }
  else
  {
    CYCLE_TIME_IN_MINS = 1;
    Set_Default_RTC();
    seriallogger_string("METER MAKE DETECTION FAILED");
    seriallogger_string("****************END*****************");
  }
delay(500);
}




void loop() {
  // put your main code here, to run repeatedly:
  server.handleClient();
  RTC();

  //if(((minutes%CYCLE_TIME_IN_MINS == 0) && (seconds == 0)) && (!reset_flag))
  if(((minutes == 0) && (seconds == 0)) && (!reset_flag))
  {
    delay(2000);
    RTC();
    seriallogger_string("RESTART");
    reset_flag = true;
    ESP.restart();
  }

  if(resume_reading == 1 && is_reading_interrupted == 1)
  {    
    delay(20000);
    resume_reading = 0;
    is_reading_interrupted = 0;
    
    seriallogger_string("RESUMING INT PROFILE READING");
    ReadInstData();//Reading Instantaneous Profile Data
    seriallogger_string("COMPLETED READING INST PROFILE DATA");

    
    seriallogger_string("RESUMING LOAD PROFILE READING");
    ReadMissingLoadProfileBlock();
    seriallogger_string("COMPLETED READING LOAD PROFILE DATA");
  }
    
  
  
#if 0
  if(seconds == 0)
  {
    //String RTC = rtc.getTime("%A, %B %d %Y %H:%M:%S");
    String RTC = (String)/*rtc.getYear()*/year + "-" + (String)/*(rtc.getMonth()+1)*/month + "-" + (String)/*rtc.getDay()*/day + " " + (String)/*rtc.getHour()*/hours + ":" + (String)/*rtc.getMinute()*/minutes + ":" + (String)/*rtc.getSecond()*/seconds;
    //Serial.println(RTC);  // (String) returns time with specified format
    seriallogger_string(RTC);  
    //seriallogger_string("\r\n");
    /*struct tm timeinfo = rtc.getTimeStruct();
    //Serial.println(&timeinfo, "%A, %B %d %Y %H:%M:%S");   //  (tm struct) Sunday, January 17 2021 07:24:38*/
  }


  //30-03-2022
  if((/*rtc.getHour()*/hours == 0) && (/*rtc.getMinute()*/minutes == 1) && (/*rtc.getSecond()*/seconds == 0))//Daily Once
  {
    /*if (!LittleFS.begin(true)) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    return;
    } */  

    BlockIDsFileName = "";
    BlockIDsFileName = "/";
    BlockIDsFileName += (String)day/*rtc.getDay()*/;  
    BlockIDsFileName += "-";
    BlockIDsFileName += (String)month/*(rtc.getMonth()+1)*/;
    BlockIDsFileName += "-";
    BlockIDsFileName += (String)year/*rtc.getYear()*/;
    BlockIDsFileName += ".txt";
                                                                                LittleFS.remove(BlockIDsFileName);                    //TO BE REMOVED
    if(!LittleFS.exists(BlockIDsFileName))
    {
      //Serial.println("\r\nCREATING BLOCK STATUS LOG FILE AS NEW DAY BEGINS\r\n");
      seriallogger_string("CREATING BLOCK STATUS LOG FILE AS NEW DAY BEGINS");
      WriteIntoBlockIDFile(BlockIDsFileName, BlockIDs, (sizeof(BlockIDs)/12));
      ReadFromFile(BlockIDsFileName);  
      /*for(int i = 0; i < (sizeof(BlockIDs)/12); i++)
      {
        //Serial.println(BlockIDs_Buffer[i]);
      }*/
    }
  }  

  //if((rtc.getMinute() == 59  || rtc.getMinute() == 15 || rtc.getMinute() == 30 || rtc.getMinute() == 45) && (rtc.getSecond() == 0))//EVERY HOUR 0TH MINUTE AND 0TH SECOND REQUEST FRAMING WILL BE DONE
  if((minutes == 0  || minutes == 15 || minutes == 30 || minutes == 45) && (seconds == 0))//EVERY HOUR 0TH MINUTE AND 0TH SECOND REQUEST FRAMING WILL BE DONE
  //if((minutes%2 == 0) && (seconds == 0))//EVERY HOUR 0TH MINUTE AND 0TH SECOND REQUEST FRAMING WILL BE DONE
  {
    //Serial.print("METER PHASE: ");
    //Serial.println(PhaseType);

    seriallogger_string("METER PHASE: ");
    seriallogger_string((String)PhaseType);
    //seriallogger_string("\r\n");

    int temp_hour = hours;
    /*if(rtc.getAmPm(true).equals("pm") && rtc.getHour() != 12)  
      temp_hour = rtc.getHour() + 12;
    else
      temp_hour = rtc.getHour();*/

    ReadInstData();//Reading Instantaneous Profile Data Every 15 minutes

    seriallogger_string("READING MISSING LOAD PROFILE BLOCKS");
    ReadMissingLoadProfileBlock();
    seriallogger_string("COMPLETED READING MISSING LOAD PROFILE BLOCKS");



    //if(rtc.getMinute() == 59)//Reading Load Profile and Missing Blocks Data Hourly Once
    if(minutes == 0 || minutes == 30)//Reading Load Profile and Missing Blocks Data Hourly Once
    {
      //delay(500);
      ReadLoadProfileData(temp_hour, minutes/*rtc.getMinute()*/, day/*rtc.getDay()*/, month/*rtc.getMonth()*/, year/*rtc.getYear()*/);//04-04-2022  
      UpdateBlockID();


      // Enable it in Final build again.
     

      //Serial.println("\r\nREADING MISSING LOAD PROFILE BLOCKS\r\n");
      seriallogger_string("READING MISSING LOAD PROFILE BLOCKS");
      ReadMissingLoadProfileBlock();
      //Serial.println("\r\nCOMPLETED READING MISSING LOAD PROFILE BLOCKS\r\n");
      seriallogger_string("COMPLETED READING MISSING LOAD PROFILE BLOCKS");

      //delay(500);
      //memset(Meter_RTC_REQframeptr, '\0', sizeof(Meter_RTC_REQframeptr));
      InitialiseESP32RTC(/*Meter_RTC_REQframeptr*/);//Sync Date Time From Meter After every Meter reading cycle
    }
   }
  delay(1000);
#endif
}


int SNRMframing()//bhavya added on 03-12-2021
{
  //HdlcConfiguration sHdlcConfig;
  char FrameType = SNRM_FRAME;
  HdlcWrapperEncoding(FrameType, 0, 0);
  return 0;
}

void HdlcWrapperEncoding(char FrameType, char *UserInformation,const size_t len)
{
  char OutBuf_Index=0;
  short  HCSlength=0;
  short  length=0;
  int CalcChecksum=0;
  char crcBytes[2];
  char userinfo_index=0;
  char FrameFormat_length[2];
  char ControlField;
  char LLS[4];
  char *userinformation;

  char Flag=0x7E;//HDLC_START_END_FLAG;
  length++;//1
  char serveraddress=0x03;

  length++;//2
  char Clientaddress=0x41;

  switch(FrameType)
  {
     case SNRM_FRAME:
            length++;
            ControlField = 0x93;
            length += 2;
            HCSlength = length;
            break;

    case INFORMATION_FRAME:
      length++;
      ControlField=GetSequenceNumber(2);
      GetSequenceNumber(1);
      length +=2;
      HCSlength=length;
      length +=2;
      length +=3;
      LLS[0]=0xE6;
      LLS[1]=0xE6;
      LLS[2]=0x00;
      length +=len;
      userinformation=UserInformation;
      break;
     
    case DISCONNECT_FRAME:
      length++;
      ControlField=0x53;
      length +=2;
      HCSlength=length;
      break;
  }
   
 
  FrameFormat_length[0]=0xA0;//HDLC_FRAME_FORMAT_WITHOUT_SEGMENTATION;
  FrameFormat_length[1]=length+2;//7

  //Hdlc_OutBuf[OutBuf_Index++]=0;
  Hdlc_OutBuf[OutBuf_Index++]=Flag;
  Hdlc_OutBuf[OutBuf_Index++]=FrameFormat_length[0];
  Hdlc_OutBuf[OutBuf_Index++]=FrameFormat_length[1];
  Hdlc_OutBuf[OutBuf_Index++]=serveraddress;
  Hdlc_OutBuf[OutBuf_Index++]=Clientaddress;
  Hdlc_OutBuf[OutBuf_Index++]=ControlField;

  CalcChecksum = hdlc_ChksumCalculate(0xFFFF, &Hdlc_OutBuf[1], (short)(HCSlength));
  CalcChecksum ^= 0xFFFF;
  Hdlc_OutBuf[OutBuf_Index++]=CalcChecksum;
  Hdlc_OutBuf[OutBuf_Index++]=(CalcChecksum >> 8);
  if(FrameType == INFORMATION_FRAME)
  {
    Hdlc_OutBuf[OutBuf_Index++]=LLS[0];
    Hdlc_OutBuf[OutBuf_Index++]=LLS[1];
    Hdlc_OutBuf[OutBuf_Index++]=LLS[2];
    while(userinfo_index<len)
    {
      ////Serial.print(userinformation[userinfo_index], HEX);
      ////Serial.print(" ");
      Hdlc_OutBuf[OutBuf_Index++]=userinformation[userinfo_index++];
    }
    ////Serial.println();

    CalcChecksum = hdlc_ChksumCalculate(0xFFFF, &Hdlc_OutBuf[1], (short)(length));
    CalcChecksum ^= 0xFFFF;
    Hdlc_OutBuf[OutBuf_Index++]=CalcChecksum;
    Hdlc_OutBuf[OutBuf_Index++]=(CalcChecksum >> 8);

  }
  Hdlc_OutBuf[OutBuf_Index]=Flag;
  //Hdlc_OutBuf[0]=OutBuf_Index;
  /*//Serial.println("*******HDLC********");
  for(int i=0; i <= OutBuf_Index; i++)
  {
    //Serial.print(Hdlc_OutBuf[i], HEX);
    //Serial.print(" ");
  }
  //Serial.println("*******HDLC********");*/
}

char GetSequenceNumber(char nAct)
{
  char cFrameType = 0;
  switch (nAct)
  {
    case 0:
      g_RRR++;
      if (g_RRR > 0x07)
        g_RRR = 0;
      break;
    case 1:
      g_SSS++;
      if (g_SSS > 0x07)
        g_SSS = 0;
      break;
    case 2:
      // RRRPSSS0
      cFrameType = 0;
      /*//Serial.print("g_RRR: ");
      //Serial.println(g_RRR);
      //Serial.println();
      //Serial.print("g_SSS: ");
      //Serial.println(g_SSS);  
      //Serial.println();  */  
      cFrameType = (char)((g_RRR << 5) | 0x10); // Receive Sequence
      /*//Serial.print("cFrameType: ");
      //Serial.println(cFrameType);
      //Serial.println();*/
      cFrameType = (char)(cFrameType | (g_SSS << 1)); // Send Seqence

    /*//Serial.print("CF: ");
    //Serial.println(cFrameType);
    //Serial.println();*/
   
    break;
    case 3:
      // RRRP0001
      cFrameType = (char)((g_RRR << 5) | 0x10); // Receive Sequence
      cFrameType = (char)(cFrameType | 0x01); // Send Seqence
      break;
  }
  return cFrameType;
}

int hdlc_ChksumCalculate(int fcs, char pcp[], int len)
{
  int i = 0;
  int j=0;
  for ( j = len; j > 0; j--)
  {
    fcs = (int)((fcs >> 8) ^ fcstab[(fcs ^ pcp[i++]) & 0xff]);
  }
  return fcs;
}

#if 0
/*LOAD REQUEST FRAMING 02-03-2022*/
//int LoadReqFrame(char LoadREQframeptr[7][MAX_SIZE], char fromDateTime[], char ToDateTime[])
int LoadReqFrame(char fromDateTime[], char ToDateTime[])
{
  char LoadREQframeptr[7][MAX_SIZE];
  int ChoppedByteCount = 0;
  int i = 0;  
  int arrindex = 0;
  char Load_dis_con=0;
  char MeterDataType = LOAD_PROFILE_DATA;
  memsetbuffer(AARQFrame, sizeof(AARQFrame));

  SNRMframing();
  hdlc_SendPacket(arrindex,LoadREQframeptr);  
  arrqframe_index=AARQ_Client_Meter_Reader_Password(/*passwordkey*/);
  char FrameType=INFORMATION_FRAME;
  HdlcWrapperEncoding(FrameType,&AARQFrame[0],arrqframe_index);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);

  //04-04-2022    
  GetSequenceNumber(0);

  DateTimeRange(Fromdate, Todate, fromDateTime, ToDateTime);

  for(i=0;i<4;i++)
  {
    MeterCommandFrame(Fromdate,Todate, MeterDataType);

    //04-04-2022    
    GetSequenceNumber(0);
   
    hdlc_SendPacket(++arrindex,LoadREQframeptr);
  }

  FrameType=DISCONNECT_FRAME;
  HdlcWrapperEncoding(FrameType,NULL,0);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);
  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  /*//Serial.println("*******LOAD FINAL********");
  for(int i=0; i < 7; i++)
  {
    for(int j=0; j < (LoadREQframeptr[i][2]+2); j++)
    {
      //Serial.print((LoadREQframeptr[i][j]), HEX);
      //Serial.print(" ");
    }
    //Serial.println();
  }
  //Serial.println("*******LOAD FINAL********");*/

  /*Read Send and Read Response from meter here. Response will be added into ResponseBuffer Global buffer.*/
  for(int reqIndex = 0; reqIndex < 7; reqIndex++)
  {
    int ResByteCount = 0;
    Serial.write( &LoadREQframeptr[reqIndex][0], (LoadREQframeptr[reqIndex][2]+2) );
    delay(1000);
    SerialRead(reqIndex, ResByteCount);

    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[reqIndex][0] != 0x7E || ResponseBuffer[reqIndex][2] == 0 || WiFi.softAPgetStationNum() > 0)
    {
        int val = WiFi.softAPgetStationNum();
         
        seriallogger_string("exiting loop because wifi status is more " + String(val));

        if(val > 0)
          is_reading_interrupted = 1;
        
        Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

        return 0;
    }

      
    //seriallogger('\n');
    //seriallogger('\n');
  }

  //Serial.println("RESPONSE BUFFER: ");
//  for(int i=0; i < 7; i++)
//  {
//    for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
//    {
//      //Serial.print((ResponseBuffer[i][j]), HEX);
//      //Serial.print(" ");
//    }
//    //Serial.println();
//  }

  //CHOPPING LOAD REPONSES WILL BE DONE HERE
  ChoppedByteCount = ChopLoadMeterResponse(ResponseBuffer);

  //Clearing Response Buffer after parsing data in it
  //memset(ResponseBuffer,0,sizeof(ResponseBuffer));  
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }
  return ChoppedByteCount;
}
#endif

void hdlc_SendPacket(int arrindex,char hdlcREQframeptr[7][MAX_SIZE])
{      
  int i = 0;
  for(i=0;i<=Hdlc_OutBuf[2]+1;i++)
  {  
    hdlcREQframeptr[arrindex][i]= Hdlc_OutBuf[i];
    ////Serial.print(hdlcREQframeptr[arrindex][i], HEX);
    ////Serial.print(" ");
  }
  ////Serial.println();
}


//char AARQ_Client_Meter_Reader_Password(char passwordkey[])
char AARQ_Client_Meter_Reader_Password()
 {
  int i = 0;
  char arrqframe_index=0;
  char length=0;
  char passLen;
  char clinetapplicationcontext[] ={0x80, 0x02, 0x02, 0x84};
  //char password_HPL[]={0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31};

  char passwordkey[LLS_Keys[METER_MAKE].length()+1] = {0};

  //seriallogger_string("AARQ METER MAKE ID " + (String)METER_MAKE);
  //seriallogger_string("AARQ " + (String)(sizeof(passwordkey) / sizeof(passwordkey[0])));
  
  
  LLS_Keys[METER_MAKE].toCharArray(passwordkey, (sizeof(passwordkey) / sizeof(passwordkey[0])));

  char password_tag []= { AARQ_AUTHVALUE, 0x02 + 0x00, 0x80, 0x00};  
  
  

  /*7E A0 50 03 41 10 FE 50 E6 E6 00 60 42 80 02 02 84
    A1 09 06 07 60 85 74 05 08 01 01
    8A 02 07 80
    8B 07 60 85 74 05 08 02 01
    AC 12 80 10 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 31 BE 10 04 0E 01 00 00 00 06 5F 1F 04 00 00 1E 1D FF FF 3F A6 7E*/

  AARQFrame[arrqframe_index++]=TAG_AARQ;
  AARQFrame[arrqframe_index++]=LENGTH;
  for(i=0;i<4;i++)
  AARQFrame[arrqframe_index++]=clinetapplicationcontext[i];
  for(i=0;i<11;i++)
  AARQFrame[arrqframe_index++]=app_ctxt_name_1[i];
  for(i=0;i<4;i++)
  AARQFrame[arrqframe_index++]=aARQ_aCSE_rEQs[i];
  for(i=0;i<9;i++)
  AARQFrame[arrqframe_index++]=auth_mech_name_1[i];
  password_tag[1] += LLS_Keys[METER_MAKE].length();
  password_tag[3] += LLS_Keys[METER_MAKE].length();
  for(i=0;i<4;i++)
  {
    //seriallogger(password_tag[i]);
    AARQFrame[arrqframe_index++]=password_tag[i];
  }
  //seriallogger('\n');
  //for(i=0;i<16;i++)//HPL
  //for(i=0;i<8;i++)//MAXWELL & SECURE
  //for(i=0;i<4;i++)//L&T
  for(i=0;i<( (sizeof(passwordkey) / sizeof(passwordkey[0])) - 1 );i++)
  {
    //seriallogger(passwordkey[i]);
    AARQFrame[arrqframe_index++]=passwordkey[i];
  }
  //seriallogger('\n');
  //auth_password_or_public_Tag_len[1] += 0x0E;
  //auth_password_or_public_Tag_len[3] += 0x0E;
  for(i=0;i<4;i++)
  {
    AARQFrame[arrqframe_index++]=auth_password_or_public_Tag_len[i];
  }
  for(i=0;i<14;i++)
  {
    AARQFrame[arrqframe_index++]=xDlmsRequest1[i];
  }    
  AARQFrame[1]=arrqframe_index-2;

  /*seriallogger_string("AARQ: ");
  for(int i = 0; i<arrqframe_index; i++)
  {
    seriallogger(AARQFrame[i]);
  }
  seriallogger('\n');*/
 
  return arrqframe_index;  
 }

 void DateTimeRange(char Fromdate[], char Todate[], char fromDateTime[], char ToDateTime[])
{            
  int tempyr;
  char fdtHour[3], fdtMin[3], fdtSec[3], fdtDate[3], fdtMonth[3],fdtYear[5];
  char todtHour[3], todtMin[3], todtSec[3], todtDate[3], todtMonth[3],todtYear[5];

  sprintf(fdtHour, "%.2s", fromDateTime); //17
  sprintf(fdtMin, "%.2s", fromDateTime + 2);  //14
  //sprintf(fdtSec, "%.2s", fromDateTime + 4);  //00
  sprintf(fdtDate, "%.2s", fromDateTime + 4); //25
  sprintf(fdtMonth, "%.2s", fromDateTime + 6);  //10
  sprintf(fdtYear, "%.4s", fromDateTime + 8); //2017

  sprintf(todtHour, "%.2s", ToDateTime);  //17
  sprintf(todtMin, "%.2s", ToDateTime + 2); //14
  //sprintf(todtSec, "%.2s", ToDateTime + 4); //00
  sprintf(todtDate, "%.2s", ToDateTime + 4);  //25
  sprintf(todtMonth, "%.2s", ToDateTime + 6); //10
  sprintf(todtYear, "%.4s", ToDateTime + 8);  //2017

  tempyr = atoi(todtYear);
  Todate[0] = (tempyr >> 8);    //20 YEAR 1
  Todate[1] = (tempyr & 0x00FF);    //17 YEAR 2
  Todate[2] = atoi(todtMonth);   //11 MONTH
  Todate[3] = atoi(todtDate);    //22 DAY
  Todate[4] = atoi(todtHour);
  Todate[5] = atoi(todtMin);

  /*//Serial.println("Todate: ");
  for(int i=0; i < 6; i++)
  {
    //Serial.print(Todate[i], HEX);
    //Serial.print(" ");
  }
  //Serial.println();*/

  tempyr = atoi(fdtYear);
  Fromdate[0] = tempyr >> 8;
  Fromdate[1] = tempyr & 0x00FF;
  Fromdate[2] = atoi(fdtMonth);
  Fromdate[3] = atoi(fdtDate);
  Fromdate[4] = atoi(fdtHour);
  Fromdate[5] = atoi(fdtMin);

  /*//Serial.println("Fromdate: ");
  for(int i=0; i < 6; i++)
  {
    //Serial.print(Fromdate[i], DEC);
    //Serial.print(" ");
  }
  //Serial.println();*/
}

void MeterCommandFrame(char Fromdate[], char Todate[], char MeterDataType)
{
  int invocationCounter = 0;
  //char Iframe;
  char Iframe[200];//changed variable to array 080221
  char MeterCommandframe_index = 0;
  char * iframe=NULL;
  char AAD[1+16+128];
  char tag_buf[50];
  char address_size=1;
  char severaddress=1;
  char clientaddress=0x41;
  char FrameType=INFORMATION_FRAME;

  /*invocationCounter++;
  Iframe[MeterCommandframe_index++] =0xC8;
  Iframe[MeterCommandframe_index++] =LENGTH;
  Iframe[MeterCommandframe_index++] =ENCRYPTION_ONLY;
  Iframe[MeterCommandframe_index++] =(invocationCounter >> 3*8) & 0xFF;
  Iframe[MeterCommandframe_index++] =(invocationCounter >> 2*8) & 0xFF;
  Iframe[MeterCommandframe_index++] =(invocationCounter >> 1*8) & 0xFF;
  Iframe[MeterCommandframe_index++] =(invocationCounter >> 0*8) & 0xFF;*/

  //printf("\r\nLOAD PROFILE STARTED\r\n");

  if(MeterDataType == LOAD_PROFILE_DATA)
  {
    MeterCommandframe_index += MeterCommandUnciperedIframe(Obiscode[ObiscodeIndex++],Fromdate, Todate, MeterDataType);
  }
  else
  {
    if(PhaseType == SINGLE_PHASE)
    {
      ////Serial.println("SINGLE PHASE");
//      if(!Get_Scalar_Flag)//14-04-2022
        MeterCommandframe_index += MeterCommandUnciperedIframe(INST_Obiscode[ObiscodeIndex++],Fromdate, Todate, MeterDataType);
//      else//14-04-2022
//        MeterCommandframe_index += MeterCommandUnciperedIframe(INST_Obiscode_Scalar[ObiscodeIndex++],Fromdate, Todate, MeterDataType);
    }
    else//THREE PHASE
    {
      ////Serial.println("THREE PHASE");
      ////Serial.println(MeterCommandframe_index);
      MeterCommandframe_index += MeterCommandUnciperedIframe(THREE_PH_INST_Obiscode[ObiscodeIndex++],Fromdate, Todate, MeterDataType);
      ////Serial.println(MeterCommandframe_index);
    }
  }
  Iframe[1]=MeterCommandframe_index-2;
  iframe=&Iframe[0];  

  /*Wrapping the data using HDLC wrapper for part1 meter */
  HdlcWrapperEncoding(FrameType,unciperIframe,MeterCommandframe_index);
}

static char MeterCommandUnciperedIframe(char Obiscodes[],char Fromdate[], char Todate[], char MeterDataType)
{
  int i = 0;
  char OutBuf_Index=0;
  char K_SUCCESS = 0;

  unciperIframe[OutBuf_Index++] = TAG_GET_REQ;
  unciperIframe[OutBuf_Index++] = REQ_GET_NORMAL;
  unciperIframe[OutBuf_Index++] = 0x81;//0xC1;//HDLCNEGOPARAMS_FORMAT;
 
  unciperIframe[OutBuf_Index++] = K_SUCCESS;

  unciperIframe[OutBuf_Index++] = Obiscodes[0];
  // 6 byte OBIS CODE A,B,C,D,E,F
  unciperIframe[OutBuf_Index++] = Obiscodes[1];
  unciperIframe[OutBuf_Index++] = Obiscodes[2];
  unciperIframe[OutBuf_Index++] = Obiscodes[3];
  unciperIframe[OutBuf_Index++] = Obiscodes[4];
  unciperIframe[OutBuf_Index++] = Obiscodes[5];
  unciperIframe[OutBuf_Index++] = Obiscodes[6];

  //14-04-2022
  if(MeterDataType == LOAD_PROFILE_DATA)
  {
    unciperIframe[OutBuf_Index++] = Obiscodes[7];
  }
  else
  {
    if(!Get_Scalar_Flag)//14-04-2022
      unciperIframe[OutBuf_Index++] = Obiscodes[7];
    else
      unciperIframe[OutBuf_Index++] = 0x03;//Obiscodes[7];
  }

  if(ObiscodeIndex == 4 && MeterDataType == LOAD_PROFILE_DATA)
  {
    unciperIframe[OutBuf_Index++] = (char)DT_ARRAY;
    unciperIframe[OutBuf_Index++] = 0x01;//length of DT_ARRAY
    unciperIframe[OutBuf_Index++] = (char)DT_STRUCTURE;
    unciperIframe[OutBuf_Index++] = 0x04;//length of DT_STRUCTURE
    unciperIframe[OutBuf_Index++] = (char)DT_STRUCTURE;
    unciperIframe[OutBuf_Index++] = STRUCT_LENGTH;
    unciperIframe[OutBuf_Index++] = (char)DT_LONG_UNSIGNED;
    unciperIframe[OutBuf_Index++] = (char)(8 >> 8);
    unciperIframe[OutBuf_Index++] = (char)(8);
    unciperIframe[OutBuf_Index++] = (char)DT_OCTET_STRING;
    unciperIframe[OutBuf_Index++] = 0x06;//length of DT_OCTET_STRING
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x01;
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0xFF;
    unciperIframe[OutBuf_Index++] = (char)DT_INTEGER;
    unciperIframe[OutBuf_Index++] = 0x02;
    unciperIframe[OutBuf_Index++] = (char)DT_LONG_UNSIGNED;
    unciperIframe[OutBuf_Index++] = 0x00; //data index
    unciperIframe[OutBuf_Index++] = 0x00;//data index
    unciperIframe[OutBuf_Index++] = (char)DT_OCTET_STRING;
    unciperIframe[OutBuf_Index++] = 0x0C;//length of DT_OCTET_STRING9       unciperIframe[OutBuf_Index++] = rload->Fromdate[0];
    unciperIframe[OutBuf_Index++] = (char)Fromdate[0];//0x07;
    unciperIframe[OutBuf_Index++] = (char)Fromdate[1];//0xE5;
    unciperIframe[OutBuf_Index++] = (char)Fromdate[2];//0x0C;
    unciperIframe[OutBuf_Index++] = (char)Fromdate[3];//0x04;
    unciperIframe[OutBuf_Index++] = 0x00;
    //unciperIframe[OutBuf_Index++] = 0x00;
    //unciperIframe[OutBuf_Index++] = 0x1E;//1E
   
    unciperIframe[OutBuf_Index++] =(char)Fromdate[4];//0x06 ;//0x05; //rload->Fromdate[4];
    unciperIframe[OutBuf_Index++] =(char)Fromdate[5]; //0x30;//rload->Fromdate[5];
   
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;//added 021120 for daily load
    //unciperIframe[OutBuf_Index++] = 0x01;//commented 021120 for daily load
    //unciperIframe[OutBuf_Index++] = 0x4A; //commented 021120 for daily load
    unciperIframe[OutBuf_Index++] = 0x00;//added 021120 for daily load
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = (char)DT_OCTET_STRING;
    unciperIframe[OutBuf_Index++] = 0x0C;//length of DT_OCTET_STRING
    unciperIframe[OutBuf_Index++] = (char)Todate[0];//0x07;
    unciperIframe[OutBuf_Index++] = (char)Todate[1];//0xE5;
    unciperIframe[OutBuf_Index++] = (char)Todate[2];//0x0C;
    unciperIframe[OutBuf_Index++] = (char)Todate[3];//0x04;  
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = (char)Todate[4];//0x06;// 0x01;//rload->Todate[4];
    unciperIframe[OutBuf_Index++] = (char)Todate[5];//0x1E;// 0x15;//rload->Todate[5];
   
    //unciperIframe[OutBuf_Index++] = 0x17;//17
    //unciperIframe[OutBuf_Index++] = 0x1E;//1e
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = 0x00;//added 021120 for daily load
    unciperIframe[OutBuf_Index++] = 0x00;//added 021120 for daily load
    //unciperIframe[OutBuf_Index++] = 0x01; commented 021120 for daily load
    // unciperIframe[OutBuf_Index++] = 0x4A; commented 021120 for daily load
    unciperIframe[OutBuf_Index++] = 0x00;
    unciperIframe[OutBuf_Index++] = (char)DT_ARRAY;
    unciperIframe[OutBuf_Index++] = 0x00;//length of DT_ARRAY */
  }
  else
  {
    unciperIframe[OutBuf_Index++] = (char)HDLC_Logical_Name;
  }

  /*//Serial.println(OutBuf_Index);
  //Serial.println("unciperIframe: ");
  for(int i = 0; i < OutBuf_Index; i++)
  {
    //Serial.print(unciperIframe[i], HEX);
    //Serial.print(" ");
  }
  //Serial.println();*/
 
  return OutBuf_Index;
}
/*LOAD REQUEST FRAMING 02-03-2022*/

/*ADMT 02-03-2022*/
//void AutoDetectMeterType(int REQindex/*,char AutoREQframeptr[][MAX_SIZE]*/)
bool AutoDetectMeterType(int REQindex)
{
  char DLMS_SNRM[] ={0x09,0x7E,0xA0,0x07,0x03,0x41,0x93,0x5A,0x64,0x7E,'\0'};
  char DLMS_LLS_Capital[] ={0x48,0x7E,0xA0,0x46,0x03,0x41,0x10,0xC5,0xD8,0xE6,0xE6,0x00,0x60,0x38,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x08,0x80,0x06,0x31,0x32,0x33,0x34,0x35,0x36,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x42,0x5F,0x7E,'\0'};
  char DLMS_LLS_LT[] ={0x46,0x7E,0xA0,0x44,0x03,0x41,0x10,0xB3,0xE1,0xE6,0xE6,0x00,0x60,0x36,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x06,0x80,0x04,0x6C,0x6E,0x74,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x1F,0x5E,0x7E,'\0'};
  char DLMS_LLS_HPL[] ={0x52,0x7E,0xA0,0x50,0x03,0x41,0x10,0xFE,0x50,0xE6,0xE6,0x00,0x60,0x42,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x12,0x80,0x10,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0xA5,0xED,0x7E,'\0'};
  char DLMS_LLS_LG[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x43,0x8A,0x7E,'\0'};
  char DLMS_LLS_SECURE[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x41,0x42,0x43,0x44,0x30,0x30,0x30,0x31,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x18,0x1D,0xFF,0xFF,0x8A,0xC8,0x7E,'\0'};
  char DLMS_LLS_GENUS[] ={0x59, 0x7E, 0xA0, 0x57, 0x03, 0x41, 0x10, 0xDF, 0x07, 0xE6, 0xE6, 0x00, 0x60, 0x49, 0xA1, 0x09, 0x06, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x01, 0x03, 0xA6, 0x0A, 0x04, 0x08, 0x47, 0x4F, 0x45, 0x30, 0x30, 0x30, 0x30, 0x30, 0x8A, 0x02, 0x07, 0x80, 0x8B, 0x07, 0x60, 0x85, 0x74, 0x05, 0x08, 0x02, 0x01, 0xAC, 0x0A, 0x80, 0x08, 0x31, 0x41, 0x32, 0x42, 0x33, 0x43, 0x34, 0x44, 0xBE, 0x17, 0x04, 0x15, 0x21, 0x13, 0x20, 0x00, 0x00, 0x00, 0x00, 0x4D, 0x0A, 0x82, 0xD1, 0x8E, 0x20, 0x47, 0xAB, 0xBD, 0xDB, 0xE9, 0xE2, 0x7C, 0x8B, 0xE9, 0xBE, 0x7E,'\0'};
  char DLMS_LLS_MAXWELL[] ={0x4A,0x7E,0xA0,0x48,0x03,0x41,0x10,0x87,0x76,0xE6,0xE6,0x00,0x60,0x3A,0x80,0x02,0x02,0x84,0xA1,0x09,0x06,0x07,0x60,0x85,0x74,0x05,0x08,0x01,0x01,0x8A,0x02,0x07,0x80,0x8B,0x07,0x60,0x85,0x74,0x05,0x08,0x02,0x01,0xAC,0x0A,0x80,0x08,0x6D,0x78,0x32,0x30,0x31,0x31,0x39,0x39,0xBE,0x10,0x04,0x0E,0x01,0x00,0x00,0x00,0x06,0x5F,0x1F,0x04,0x00,0x00,0x1E,0x1D,0xFF,0xFF,0x3F,0xE1,0x7E,'\0'};//MAXWELL 04-04-2022
  char DLMSCommand_END[] ={0x09,0x7E,0xA0,0x07,0x03,0x41,0x53,0x56,0xA2,0x7E,'\0'};
  char DLMSCommand_MeterType[]={0x1B,0x7E,0xA0,0x19,0x03,0x41,0x32,0x3A,0xBD,0xE6,0xE6,0x00,0xC0,0x01,0xC1,0x00,0x01,0x00,0x00,0x5E,0x5B,0x09,0xFF,0x02,0x00,0x52,0x9E,0x7E,'\0'};
  char ADMTreqptr[4][MAX_SIZE] = {0};
  int arrayindex = 0;
  blockcopy(ADMTreqptr,DLMS_SNRM,arrayindex);
  switch(REQindex)
  {
    case SECURE:
      blockcopy(ADMTreqptr,DLMS_LLS_SECURE,++arrayindex);
      break;
    case LG:
      blockcopy(ADMTreqptr,DLMS_LLS_LG,++arrayindex);
      break;
    case LT:
      blockcopy(ADMTreqptr,DLMS_LLS_LT,++arrayindex);
      break;
    case HPL:
      blockcopy(ADMTreqptr,DLMS_LLS_HPL,++arrayindex);
      break;
    case CAP:
      blockcopy(ADMTreqptr,DLMS_LLS_Capital,++arrayindex);
      break;
    case GENUS:
      blockcopy(ADMTreqptr,DLMS_LLS_GENUS,++arrayindex);
      break;
    case MAXWELL:
      blockcopy(ADMTreqptr,DLMS_LLS_MAXWELL,++arrayindex);
      break;
  }
  blockcopy(ADMTreqptr,DLMSCommand_MeterType,++arrayindex);
  blockcopy(ADMTreqptr,DLMSCommand_END,++arrayindex);
  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  /*//Serial.println("***************");
  for(int i=0; i < 4; i++)
  {
    for(int j=0; j < (ADMTreqptr[i][2]+2); j++)
    {
      //Serial.print((ADMTreqptr[i][j]), HEX);
      //Serial.print(" ");
    }
    //Serial.println();
  }
  //Serial.println("***************");*/

  /*Read Send and Read Response from meter here. Response will be added into ResponseBuffer Global buffer.*/
  for(int reqIndex = 0; reqIndex < ( sizeof (ADMTreqptr) / sizeof (ADMTreqptr[0]) ); reqIndex++)
  {
    int ResByteCount = 0;
    Serial.write( &ADMTreqptr[reqIndex][0], (ADMTreqptr[reqIndex][2]+2) );
    //delay(300);
    SerialRead(reqIndex, ResByteCount);

    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[reqIndex][0] != 0x7E || ResponseBuffer[reqIndex][2] == 0)
    {
      seriallogger_string("NO RESPONSE");
      return false;
    }

    if(reqIndex == 1)//if it is AARQ Req, check for ASSC status in response before proceeding to next request
    {
      if((ResponseBuffer[reqIndex][25] == 0x03 && ResponseBuffer[reqIndex][26] == 0x02 && ResponseBuffer[reqIndex][27] == 0x01 && ResponseBuffer[reqIndex][28] == 0x01) || 
        (ResponseBuffer[reqIndex][29] == 0x03 && ResponseBuffer[reqIndex][30] == 0x02 && ResponseBuffer[reqIndex][31] == 0x01 && ResponseBuffer[reqIndex][32] == 0x01) )
      {
        //seriallogger_string("ASSC FAILED");
        return false;
      }
    }
      
    //seriallogger('\n');
    //seriallogger('\n');
  }

  /*seriallogger_string("RESPONSE BUFFER: ");
  for(int i=0; i < 4; i++)
  {
    for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
    {
      seriallogger((ResponseBuffer[i][j]));
    }
    seriallogger('\n');
  }*/

  /*Parsing Meter Category Type Here*/
  METER_MAKE = REQindex;
  ParseMeterCategoryType(ResponseBuffer);

  //Clearing Response Buffer after parsing data in it
  //memset(ResponseBuffer,0,sizeof(ResponseBuffer));  
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }
  return true;
}

void blockcopy(char destarray[4][MAX_SIZE],char srcarray[],int arrindex)
{
   int i=0;
   for(i=0; i<=srcarray[0]-1; i++)
    {
      destarray[arrindex][i] = srcarray[i+1];
    }  
}
/*ADMT 02-03-2022*/

/*INST REQ FRAMING 03-03-2022*/
int InstReqFrame(char REQframeptr[][MAX_SIZE], int PhaseType)
{
  int ChoppedByteCount = 0;
  int i = 0;  
  int arrindex = 0;
  char Load_dis_con=0;
  int no_of_Req = 0;
  char MeterDataType = INSTANTANEOUS_DATA;
  memsetbuffer(AARQFrame, sizeof(AARQFrame));
  
  SNRMframing();
  hdlc_SendPacket(arrindex,REQframeptr);  
  arrqframe_index=AARQ_Client_Meter_Reader_Password(/*passwordkey*/);
  char FrameType=INFORMATION_FRAME;
  HdlcWrapperEncoding(FrameType,&AARQFrame[0],arrqframe_index);
  hdlc_SendPacket(++arrindex,REQframeptr);

  //04-04-2022    
  GetSequenceNumber(0);
 
  if(PhaseType == SINGLE_PHASE)
    no_of_Req = SINGLE_PH_PARAM_COUNT;
  else
    no_of_Req = THREE_PH_PARAM_COUNT;

  ////Serial.println(no_of_Req);
 
  for(i=0;i<no_of_Req;i++)
  {
    MeterCommandFrame(NULL,NULL, MeterDataType);

    //04-04-2022    
    GetSequenceNumber(0);
   
    hdlc_SendPacket(++arrindex,REQframeptr);
  }

  FrameType=DISCONNECT_FRAME;
  HdlcWrapperEncoding(FrameType,NULL,0);
  hdlc_SendPacket(++arrindex,REQframeptr);
  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  /*seriallogger_string("*******INSTANTANEOUS FINAL********");
  for(int i=0; i < ( no_of_Req + ASSC_REQ_COUNT ); i++)
  {
    for(int j=0; j < (REQframeptr[i][2]+2); j++)
    {
      seriallogger((REQframeptr[i][j]));
    }
    seriallogger('\n');
  }
  seriallogger_string("*******INSTANTANEOUS FINAL********");*/

  seriallogger_string("SENDING INST COMMANDS");
  seriallogger_string((String)( no_of_Req + ASSC_REQ_COUNT ));
  /*Read Send and Read Response from meter here. Response will be added into ResponseBuffer Global buffer.*/
  for(int reqIndex = 0; reqIndex < ( no_of_Req + ASSC_REQ_COUNT ); reqIndex++)
  {
    int ResByteCount = 0;

    /*for(int j=0; j < (REQframeptr[reqIndex][2]+2); j++)
    {
      seriallogger((REQframeptr[reqIndex][j]));
    }
    seriallogger('\n');*/
    
    Serial.write( &REQframeptr[reqIndex][0], (REQframeptr[reqIndex][2]+2) );
    //delay(300);
    SerialRead(reqIndex, ResByteCount);
    //delay(1000);

    /*for(int j=0; j < (ResponseBuffer[reqIndex][2]+2); j++)
    {
      seriallogger((ResponseBuffer[reqIndex][j]));
    }    
    seriallogger('\n');*/
  

    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[reqIndex][0] != 0x7E || ResponseBuffer[reqIndex][2] == 0 || WiFi.softAPgetStationNum() > 0)
    {
        int val = WiFi.softAPgetStationNum();
         
        seriallogger_string("exiting loop because wifi status is more " + String(val));
        
        if(val > 0)
          is_reading_interrupted = 1;
        
        Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

      return 0;      
    }      
    //seriallogger('\n');
    //seriallogger('\n');
  }
  seriallogger_string("COMPLETED INST COMMANDS");
  /*seriallogger_string("INSTANTANEOUS RESPONSE BUFFER: ");
  for(int i=0; i < ( no_of_Req + ASSC_REQ_COUNT ); i++)
  {
    for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
    {
      seriallogger((ResponseBuffer[i][j]));
    }    
    seriallogger('\n');
  }*/

  //CHOPPING INST REPONSES WILL BE DONE HERE
  if(!Get_Scalar_Flag)//14-04-2022
    ChoppedByteCount = ChopInstMeterResponse(ResponseBuffer, PhaseType);
  else//14-04-2022
  {
    ChoppedByteCount = ChopInstScalarMeterResponse(ResponseBuffer, PhaseType);
    Get_Scalar_Flag = false;
  }

  //Clearing Response Buffer after parsing data in it
  //memset(ResponseBuffer,0,sizeof(ResponseBuffer));  
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }  
  return ChoppedByteCount;  
}
/*INST REQ FRAMING 03-03-2022*/


/*READ METER DATE TIME ONLY 08-03-2022*/
//void InitialiseESP32RTC(/*char REQframeptr[][MAX_SIZE]*/)
bool InitialiseESP32RTC()
{
  char Meter_RTC_REQframeptr[4][MAX_SIZE];
  int i = 0;  
  int arrindex = 0;
  int no_of_Req = 0;
  char MeterDataType = INSTANTANEOUS_DATA;
  memsetbuffer(AARQFrame, sizeof(AARQFrame));
  
  SNRMframing();
  hdlc_SendPacket(arrindex,Meter_RTC_REQframeptr);  
  arrqframe_index=AARQ_Client_Meter_Reader_Password();  
  char FrameType=INFORMATION_FRAME;
  HdlcWrapperEncoding(FrameType,&AARQFrame[0],arrqframe_index);
  hdlc_SendPacket(++arrindex,Meter_RTC_REQframeptr);

  //04-04-2022    
  GetSequenceNumber(0);
 
  for(i=0;i<METER_RTC_READ_REQ_COUNT;i++)
  {
    MeterCommandFrame(NULL,NULL, MeterDataType);
    hdlc_SendPacket(++arrindex,Meter_RTC_REQframeptr);
  }

  FrameType=DISCONNECT_FRAME;
  HdlcWrapperEncoding(FrameType,NULL,0);
  hdlc_SendPacket(++arrindex,Meter_RTC_REQframeptr);
  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  /*for(int i=0; i < 4; i++)
  {
    for(int j=0; j < (Meter_RTC_REQframeptr[i][2]+2); j++)
    {
      //Serial.print((Meter_RTC_REQframeptr[i][j]), HEX);
      //Serial.print(" ");
    }
    //Serial.println();
  } */

  /*Read Send and Read Response from meter here. Response will be added into ResponseBuffer Global buffer.*/
  for(int reqIndex = 0; reqIndex < ( sizeof (Meter_RTC_REQframeptr) / sizeof (Meter_RTC_REQframeptr[0]) ); reqIndex++)
  {
    int ResByteCount = 0;
    Serial.write( &Meter_RTC_REQframeptr[reqIndex][0], (Meter_RTC_REQframeptr[reqIndex][2]+2) );  
    //delay(500);
    SerialRead(reqIndex, ResByteCount);

    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[reqIndex][0] != 0x7E || ResponseBuffer[reqIndex][2] == 0)
      return false;
    
    //seriallogger('\n');
    //seriallogger('\n');    
  }
  //seriallogger_string("\r\nDONE WITH DATE TIME READING\r\n");
 
  /*seriallogger_string("RESPONSE BUFFER: ");
  for(int i=0; i < 4; i++)
  {
    for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
    {
      seriallogger((ResponseBuffer[i][j]));
    }
    seriallogger('\n');
  }*/

  /*Parse and initialise RTC here*/
  DateTimeParsing(ResponseBuffer);

  //Clearing Response Buffer after parsing data in it
  //memset(ResponseBuffer,0,sizeof(ResponseBuffer));  
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }

   //String sync_RTC = (String)/*rtc.getYear()*/year + "-" + (String)/*(rtc.getMonth()+1)*/month + "-" + (String)/*rtc.getDay()*/day + " " + (String)/*rtc.getHour()*/hours + ":" + (String)/*rtc.getMinute()*/minutes + ":" + (String)/*rtc.getSecond()*/seconds;
  if((month == 0 || month > 12) || (day == 0 || day > 31) || hours > 23 || minutes > 59 || seconds > 59 || year < 2022)
    return false;
  
  return true;
}
/*READ METER DATE TIME ONLY 03-03-2022*/


/*WRITE INTO FILE*/
void WriteIntoFile(String WriteFileName, char FileContent[][MAX_SIZE], int FileContentSize)
{
  /*if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    return;
  }*/
  LittleFS.remove(WriteFileName);
  File file = LittleFS.open(WriteFileName, "a");
 
  if (!file) {
    //Serial.println("There was an error opening the file for writing");
    return;
  }

  //Serial.println(FileContentSize);

  for(int i=0; i < FileContentSize; i++)
  {
    for(int j=0; j < (FileContent[i][2]+2); j++)
    {
      file.print((FileContent[i][j]), HEX);
      file.print(" ");
    }
    file.println();
  }

 
  /*if (file.println(FileContent)) {
    //Serial.println("File was written");
  } else {
    //Serial.println("File write failed");
  }*/
 
  file.close();
}
/*WRITE INTO FILE*/

/*READ FROM FILE*/
void ReadFromFile(String ReadFileName)
{
  //File file2 = LittleFS.open(ReadFileName);
  File file2 = LittleFS.open(ReadFileName, "r");
 
  if(!file2){
      //Serial.println("Failed to open file for reading");
      seriallogger_string("Failed to open file for reading");
      return;
  }

  //seriallogger_string(ReadFileName);

  ////Serial.println("File Content: ");

  char bufferc[1024];//30-03-2022
  String line = "";//30-03-2022
  int line_index = 0;//30-03-2022
  
  while(file2.available())
  {
      //Serial.write(file2.read());//Original

      //30-03-2022
      int a = file2.readBytesUntil('\n', bufferc, sizeof(bufferc));      
      bufferc[a] = 0;
      BlockIDs_Buffer[line_index] = bufferc;
      ////Serial.println(BlockIDs_Buffer[line_index]);
      line_index++;
      ////Serial.println(line);
  }
  ////Serial.println();
  ////Serial.println();
  file2.close();
}
/*READ FROM FILE*/

/*READ FROM SERIAL*/
void SerialRead(int reqIndex, int ResByteCount)
{ 
  int wait_count = 0; 
  /*int start_sec = seconds;
  while((seconds - start_sec) < 5) 
  {*/
    RTC();
    ////Serial.print("RES: ");
    while(Serial.available() >= 0)
    {
      if (Serial.available())
      {
        wait_count = 0;
        // read the incoming byte:
        incomingByte = Serial.read();
        //seriallogger(incomingByte);
 
        // say what you got:
        ////Serial.print(incomingByte, HEX);
        ////Serial.print(" ");

        ResponseBuffer[reqIndex][ResByteCount++] = (char)incomingByte;
      }
      else
      {
        //If not data is available then exit reading
        ////Serial.println("NO DATA AVAILABLE");
        wait_count++;
        if(wait_count > 10)
        {
          break;
        }
        delay(100);
      }
    }
    //seriallogger_string("NO. OF BYTES READ: " + ResByteCount);
    //if(ResByteCount ==  (ResponseBuffer[reqIndex][2]+2))
    //  break;
  //}
  //seriallogger_string("NO. OF BYTES READ: " + ResByteCount);
    //seriallogger('\n');
    ////Serial.println();
    ////Serial.println("EXITING READING");
}
/*READ FROM SERIAL*/

/*PARSE METER RTC*/
void DateTimeParsing(char ResponseBuffer[][MAX_SIZE_RESPONSE_BUFFER])
{
  /*int year = 0;
  byte month = 0;
  byte day = 0;
  byte hour = 0;
  byte mins = 0;
  byte sec = 0;
  int startColumnIndex = 17;
  int startRowIndex = 2;
  year = (int)((ResponseBuffer[startRowIndex][startColumnIndex] << 8) | (ResponseBuffer[startRowIndex][startColumnIndex + 1]));
  month = ResponseBuffer[startRowIndex][startColumnIndex + 2];
  day = ResponseBuffer[startRowIndex][startColumnIndex + 3];  
  hour = ResponseBuffer[startRowIndex][startColumnIndex + 5];
  mins = ResponseBuffer[startRowIndex][startColumnIndex + 6];
  sec = ResponseBuffer[startRowIndex][startColumnIndex + 7];
  //rtc.setTime(55, 59, 13, 9, 3, 2022);  // 09th Mar 2022 13:59:55 //ASSIGN OBTAINED RTC FROM METER TO ESP32 HERE  
  rtc.setTime(sec, mins, hour, day, month, year);*/
  //seriallogger_string("\r\nPARSING DT\r\n");
  int local_year = 0;
  byte local_month = 0;
  byte local_day = 0;
  byte local_hour = 0;
  byte local_mins = 0;
  byte local_sec = 0;
  int startColumnIndex = 17;
  int startRowIndex = 2;
  year = local_year = (int)((ResponseBuffer[startRowIndex][startColumnIndex] << 8) | (ResponseBuffer[startRowIndex][startColumnIndex + 1]));
  month = local_month = ResponseBuffer[startRowIndex][startColumnIndex + 2];
  day = local_day = ResponseBuffer[startRowIndex][startColumnIndex + 3];  
  startingHour = hours = local_hour = ResponseBuffer[startRowIndex][startColumnIndex + 5];
  minutes = local_mins = ResponseBuffer[startRowIndex][startColumnIndex + 6];
  seconds = local_sec = ResponseBuffer[startRowIndex][startColumnIndex + 7];
  //rtc.setTime(55, 59, 13, 9, 3, 2022);  // 09th Mar 2022 13:59:55 //ASSIGN OBTAINED RTC FROM METER TO ESP32 HERE
  //rtc.setTime(55/*local_sec*/, 59/*local_mins*/, local_hour, local_day, local_month, local_year); //Commented on 25-03-2022 as ESP8266  doesn't have internal RTC.
  //seriallogger_string("\r\nDONE WITH DT PARSING\r\n");
  //hours = 10;minutes = 57;
  String sync_RTC = (String)/*rtc.getYear()*/year + "-" + (String)/*(rtc.getMonth()+1)*/month + "-" + (String)/*rtc.getDay()*/day + " " + (String)/*rtc.getHour()*/hours + ":" + (String)/*rtc.getMinute()*/minutes + ":" + (String)/*rtc.getSecond()*/seconds;
  seriallogger_string("Sync Date Time: " + sync_RTC);
}
/*PARSE METER RTC*/

/*PARSE METER CATEGORY TYPE*/
void ParseMeterCategoryType(char ResponseBuffer[][MAX_SIZE_RESPONSE_BUFFER])
{
  int startColumnIndex = 0;//16 for HPL and L&T Meters and SECURE //17 for MAXWELL

  if(METER_MAKE == 6)
    startColumnIndex = 17;
  else
    startColumnIndex = 16;
  
  int startRowIndex = 2;
  MeterCategoryType = ResponseBuffer[startRowIndex][startColumnIndex];

  //30-03-2022
  if(MeterCategoryType == 5 || MeterCategoryType == 6)//SINGLE PHASE AC STATIC METERS
    PhaseType = 1;
   else
    PhaseType = 3;//THREE PHASE METERS
 
  //Serial.print("Meter Category Type: ");
  //Serial.println(MeterCategoryType);
  //Serial.println();

  seriallogger_string("Meter Category Type: " + (String)MeterCategoryType);
  //seriallogger_string("\r\n");
 
}
/*PARSE METER CATEGORY TYPE*/

/*CHOP INTANTANEOUS METER RESPONSE*/
int ChopInstMeterResponse(char ResponseBuffer[][MAX_SIZE_RESPONSE_BUFFER], int PhaseType)
{
  int no_of_Res = 0;
  int startRowIndex =2;
  int startColumnIndex = 15;
  int choppedBufIndex =0;
  int temp_MSN_Index = 0;
  if(PhaseType == SINGLE_PHASE)
    no_of_Res = SINGLE_PH_PARAM_COUNT;
  else if(PhaseType == THREE_PHASE)
    no_of_Res = THREE_PH_PARAM_COUNT;

  for(int resIndex = startRowIndex; resIndex < (no_of_Res+2); resIndex++)
  {
    for(int resColumnIndex = startColumnIndex; resColumnIndex < ((ResponseBuffer[resIndex][2]+2)-3); resColumnIndex++, choppedBufIndex++)
    {
      Chopped_Inst_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex];

      //PARSE METER SERIAL NO. RESPONSE //30-03-2022
      if(resIndex == ((no_of_Res+2)-1))
      {

        /*//Serial.println("Hellooooooooooooooooooooooooooooo");
        //Serial.println(ResponseBuffer[resIndex][startColumnIndex]);*/
        if(ResponseBuffer[resIndex][startColumnIndex] == 0x06)//Unsigned Long
        {
          //if(resIndex == ((no_of_Res+2)-1))
          {
            ParsedMeterSerialNo = ((ParsedMeterSerialNo << 8) | ResponseBuffer[resIndex][resColumnIndex]);
            MeterSerialNo_Final = (String)ParsedMeterSerialNo;
          }
        }
        else if(ResponseBuffer[resIndex][startColumnIndex] == 0x09 && resColumnIndex >= (startColumnIndex+2))//OCTET STRING
        {
          char temp_MSN[ResponseBuffer[resIndex][startColumnIndex+1]];
          temp_MSN[temp_MSN_Index++] = ResponseBuffer[resIndex][resColumnIndex];
          temp_MSN[temp_MSN_Index] = '\0';

          ////Serial.println(ResponseBuffer[resIndex][resColumnIndex], HEX);
         
          String temp = temp_MSN;
          /*//Serial.print("temp: ");
          //Serial.println(temp);*/
          MeterSerialNo_Final = (String)temp;
        }
      }
    }
  }

  //Serial.println();
  //Serial.println("INST DATA: ");
  for(int i = 0; i < choppedBufIndex; i++)
  {
    //Serial.print(Chopped_Inst_DataBuffer[i], HEX);
    //Serial.print(" ");
  }
  //Serial.println();
  return (choppedBufIndex);
}
/*CHOP INTANTANEOUS METER RESPONSE*/

/*CHOP INTANTANEOUS SCALAR METER RESPONSE 14-04-2022*/
int ChopInstScalarMeterResponse(char ResponseBuffer[][MAX_SIZE_RESPONSE_BUFFER], int PhaseType)
{
  int no_of_Res = 0;
  int startRowIndex =2;
  int startColumnIndex = 15;
  int choppedBufIndex =0;
  int temp_MSN_Index = 0;
  if(PhaseType == SINGLE_PHASE)
    no_of_Res = SINGLE_PH_PARAM_COUNT;
  else if(PhaseType == THREE_PHASE)
    no_of_Res = THREE_PH_PARAM_COUNT;

  for(int resIndex = startRowIndex; resIndex < (no_of_Res+2); resIndex++)
  {
    for(int resColumnIndex = startColumnIndex; resColumnIndex < ((ResponseBuffer[resIndex][2]+2)-3); resColumnIndex++, choppedBufIndex++)
    {
      Chopped_Inst_Scalar_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex];
    }
  }

  //Serial.println();
  //Serial.println("INST SCALAR DATA: ");
  for(int i = 0; i < choppedBufIndex; i++)
  {
    //Serial.print(Chopped_Inst_Scalar_DataBuffer[i], HEX);
    //Serial.print(" ");
  } 
  //Serial.println();
  return (choppedBufIndex);
}
/*CHOP INTANTANEOUS SCALAR METER RESPONSE 14-04-2022*/

/*CHOP Load METER RESPONSE*/
int ChopLoadMeterResponse(char ResponseBuffer[][MAX_SIZE_RESPONSE_BUFFER], int req_count)
{
  int ChoppedByteCount = 0;
  int no_of_Res = req_count;//7;
  int startRowIndex =2;//14-04-2022 chnaged from 5 to 2
  int startColumnIndex = 15;
  int choppedBufIndex =0;
  bool SUPERVISORY_RES = false;
    
  for(int resIndex = startRowIndex; resIndex < (no_of_Res-1); resIndex++)
  {
    for(int resColumnIndex = startColumnIndex; resColumnIndex < ((ResponseBuffer[resIndex][2]+2)-3); resColumnIndex++, choppedBufIndex++)
    {
      if(SUPERVISORY_RES)
        Chopped_Load_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex];
      else if(ResponseBuffer[resIndex][12] == 0x01)
        Chopped_Load_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex];
      else
        Chopped_Load_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex+6];
    }
    //Serial.println(choppedBufIndex);
    if(ResponseBuffer[resIndex][1] == 0xA8)
    {
      Serial.println("SUPER TRUE: " + (String)resIndex);
      SUPERVISORY_RES = true;
      startColumnIndex = 8;
    }
    else    
    {
      Chopped_Load_DataBuffer[choppedBufIndex++] = 0x2A;//14-04-2022
      SUPERVISORY_RES = false;
      startColumnIndex = 15;
    }
  }
   
//  for(int resIndex = startRowIndex; resIndex < (no_of_Res-1); resIndex++)
//  {
//    if(ResponseBuffer[resIndex][0] != 0x7E || ResponseBuffer[resIndex][2] == 0)
//      return 0 ;
//    
//    for(int resColumnIndex = startColumnIndex; resColumnIndex < ((ResponseBuffer[resIndex][2]+2)-3); resColumnIndex++, choppedBufIndex++)
//    {
//      if(ResponseBuffer[resIndex][12] == 0x01)
//        Chopped_Load_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex];
//      else
//        Chopped_Load_DataBuffer[choppedBufIndex] = ResponseBuffer[resIndex][resColumnIndex+6];
//    }
//    Chopped_Load_DataBuffer[choppedBufIndex++] = 0x2A;//14-04-2022
//  }



  //Serial.println();
  //Serial.println("LOAD DATA: ");
  /*for(int i = 0; i < choppedBufIndex; i++)
  {
    //Serial.print(Chopped_Load_DataBuffer[i], HEX);
    //Serial.print(" ");
  } */ 
  //Serial.println();
  return (choppedBufIndex);
}
/*CHOP Load METER RESPONSE*/

/*WRITE INTO POST DATA FILE*/
/*void PostData_WriteIntoFile(String WriteFileName, char FileContent[], int FileContentSize)
{
  /*if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    return;
  }*/
/*  LittleFS.remove(WriteFileName);
  File file = LittleFS.open(WriteFileName, "a");
 
  if (!file) {
    //Serial.println("There was an error opening the file for writing");
    return;
  }

  //Serial.println(FileContentSize);

  for(int i=0; i < FileContentSize; i++)
  {  
    file.print((FileContent[i]), HEX);
    file.print(" ");    
  }

 
  /*if (file.println(FileContent)) {
    //Serial.println("File was written");
  } else {
    //Serial.println("File write failed");
  }*/
 
/*  file.close();
}*/
/*WRITE INTO POST DATA FILE*/

/*WRITE INTO BLOCK ID FILE*///30-03-2022
void WriteIntoBlockIDFile(String WriteFileName, String FileContent[], int FileContentSize)
{
  /*if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    seriallogger_string("An Error has occurred while mounting LittleFS");
    return;
  }*/
                                                                                              //LittleFS.remove(WriteFileName);
  File file = LittleFS.open(WriteFileName, "w");

  //Serial.println("\r\n\r\nFILE NAME :");
  //Serial.println(WriteFileName);

  seriallogger_string("FILE NAME:" + WriteFileName);
  //seriallogger_string(WriteFileName);
  //seriallogger_string("\r\n");
  if (!file) {
    //Serial.println("There was an error opening the file for writing");
    seriallogger_string("There was an error opening the file for writing");
    return;
  }

  ////Serial.println(FileContentSize);

  for(int i=0; i < FileContentSize; i++)
  {  
      file.println((FileContent[i]));
  }

 
  /*if (file.println(FileContent)) {
    //Serial.println("File was written");
  } else {
    //Serial.println("File write failed");
  }*/
 
  file.close();
}
/*WRITE INTO BLOCK ID FILE*/

/*WRITE POST DATA INTO BLOCK ID FILE*///30-03-2022
void WritePostDataIntoBlockIDFile(String WriteFileName, String FileContent)
{
  /*if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    seriallogger_string("An Error has occurred while mounting LittleFS");
    return;
  }*/

  if(FileContent.length() <= 0)
    return;

  //IF EXISTS, REMOVE THE FILE 13-04-2022
  if(LittleFS.exists(WriteFileName))
  {
    LittleFS.remove(WriteFileName);
  }
 
  File file = LittleFS.open(WriteFileName, "w");

  ////Serial.println(WriteFileName);
  if (!file) {
    //Serial.println("There was an error opening the file for writing");
    seriallogger_string("There was an error opening the file for writing");
    return;
  }    
  //file.println(FileContent);
   
  if (file.println(FileContent)) {
    //Serial.println("File was written");
    seriallogger_string("File was written");
    if(WriteFileName.indexOf("_I.txt") >= 0)
    {
      WriteIntoFile("/InstDataStatus.txt", WriteFileName);
      seriallogger_string("INST DATA FLAG SET: " + WriteFileName);
    }
    
  } else {
    //Serial.println("File write failed");
    seriallogger_string("File write failed");
  } 
  file.close();
}
/*WRITE POST DATA INTO BLOCK ID FILE*/

/*READ LOAD PROFILE BLOCK*/
bool ReadLoadProfileData(int hour, int minutes, int day, int month, int year)
{
    char fromDateTime[14];// = "100003032022";
    char ToDateTime[14];// = "110003032022";
    char temp[12];

    if(METER_MAKE == 6)
      sprintf(fromDateTime, "%02s", (String)(hour-1));
    else 
      sprintf(fromDateTime, "%02s", (String)(hour));


    sprintf(temp, "%02s", (String)0);
    strcat(fromDateTime, temp);
    sprintf(temp, "%02s", (String)day);
    strcat(fromDateTime, temp);
    sprintf(temp, "%02s", (String)(month));
    strcat(fromDateTime, temp);
    sprintf(temp, "%04s", (String)year);
    strcat(fromDateTime, temp);    
    //Serial.println(fromDateTime);
    seriallogger_string((String)fromDateTime);
    //seriallogger_string("\r\n");

    sprintf(ToDateTime, "%02s", (String)(hour));

    if(METER_MAKE == 6)
      sprintf(temp, "%02s", (String)0);//MAXWELL MINUTES
    else
      sprintf(temp, "%02s", (String)59);

      
    strcat(ToDateTime, temp);
    sprintf(temp, "%02s", (String)day);
    strcat(ToDateTime, temp);
    sprintf(temp, "%02s", (String)(month));
    strcat(ToDateTime, temp);
    sprintf(temp, "%04s", (String)year);
    strcat(ToDateTime, temp);    
    //Serial.println(ToDateTime);
    seriallogger_string((String)ToDateTime);
    //seriallogger_string("\r\n");

    //Serial.println();
    //Serial.println("Load Data Read Started...");
    //Serial.println();
       
    //seriallogger_string("Load Data Read Started...");
   
   
    int Load_ChoppedByteCount = temp_LoadReqFrame(/*REQframeptr,*/ fromDateTime, ToDateTime);
    ////Serial.println(Load_ChoppedByteCount);
    //Serial.println("Load Data Read Completed.");  
    //seriallogger_string("Load Data Read Completed.");  
    //Serial.println();

    //FILE READ WRITE OPERATIONS START
    /*FileContentSize = (sizeof (REQframeptr) / sizeof (REQframeptr[0]));
    WriteIntoFile("/REQframeptr.txt", REQframeptr, FileContentSize);
    ReadFromFile("/REQframeptr.txt");*/

    if(Load_ChoppedByteCount != 0)
    {
       //seriallogger_string((String)Load_ChoppedByteCount);  
       CreateLoadDataFile(Load_ChoppedByteCount, day, hour);//hour is the block ID or number  //temp_day is the day of which load data is being read
       return true;
    }
    else
    {
      return false;
    }
}
/*READ LOAD PROFILE BLOCK*/

/*CREATE AND WRITE INST DATA FILE*/
void CreateInstDataFile(int Inst_ChoppedByteCount, int Inst_Scalar_ChoppedByteCount)
{
    char temp[5];
    String FinalInst_str = "$";
    FinalInst_str += global_NodeID;
    FinalInst_str += "_";
    FinalInst_str += (String)PhaseType;
    FinalInst_str += "_";
    FinalInst_str += "I";
    FinalInst_str += "_";
    FinalInst_str += MeterSerialNo_Final;
    FinalInst_str += "_";
    //seriallogger_string("\r\n");
    //seriallogger_string(FinalInst_str);
    for(int i = 0; i < Inst_ChoppedByteCount; i++)
    {
      FinalInst_str += (uint8_t)Chopped_Inst_DataBuffer[i];
      FinalInst_str += " ";
    }
    FinalInst_str.trim();
    FinalInst_str += "*";//14-04-2022 replaced $ with *

    //14-04-2022
    for(int i = 0; i < Inst_Scalar_ChoppedByteCount; i++)
    {
      FinalInst_str += (uint8_t)Chopped_Inst_Scalar_DataBuffer[i];
      FinalInst_str += " ";
    }
    FinalInst_str.trim();
    FinalInst_str += "$";

    
    //Serial.println();                  
    //Serial.println("FINAL INST STRING");
    //Serial.println(FinalInst_str);
    //Serial.println();

    //seriallogger_string("\r\n");                  
    seriallogger_string(/*"FINAL INST STRING: " + */FinalInst_str);
    
    
    //seriallogger_string(FinalInst_str);
 
    
    
    //seriallogger_string("\r\n");
   
   
    String Inst_Data_FIle_With_BlockID = "";
    //char temp_Char_Array[4];
    //memset(temp_Char_Array, 0, sizeof(temp_Char_Array));//04-04-2022
    memsetbuffer(temp_Char_Array, sizeof(temp_Char_Array));
    
    /*if(rtc.getAmPm(true).equals("pm") && rtc.getHour() != 12)  
      sprintf(temp_Char_Array, "%02s", (String)(rtc.getHour() + 12));
    else
      sprintf(temp_Char_Array, "%02s", (String)(rtc.getHour()));*/
    sprintf(temp_Char_Array, "%02s", (String)(hours));


    Inst_Data_FIle_With_BlockID = "/meterreadingdata"; //13-04-2022
    Inst_Data_FIle_With_BlockID += "/";
    Inst_Data_FIle_With_BlockID += temp_Char_Array;//BlockID
    /*//Serial.print("\r\nBlockID: ");
    //Serial.println(Inst_Data_FIle_With_BlockID);*/
    Inst_Data_FIle_With_BlockID += "_";
    /*Inst_Data_FIle_With_BlockID += (String)PhaseType;
    Inst_Data_FIle_With_BlockID += "_";
    Inst_Data_FIle_With_BlockID += (String)MeterCategoryType;
    Inst_Data_FIle_With_BlockID += "_";
    Inst_Data_FIle_With_BlockID += MeterSerialNo_Final;*/

    sprintf(temp, "%02s", (String)day);
    Inst_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%02s", (String)month);
    Inst_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%04s", (String)year);
    Inst_Data_FIle_With_BlockID += temp;
    Inst_Data_FIle_With_BlockID += "_";
    sprintf(temp, "%02s", (String)hours);
    Inst_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%02s", (String)minutes);
    Inst_Data_FIle_With_BlockID += temp;
    
    Inst_Data_FIle_With_BlockID += "_";
    Inst_Data_FIle_With_BlockID += "I.txt";
    //Serial.println();
    //Serial.print("\r\nInst BlockID FILE NAME: ");
    //Serial.println(Inst_Data_FIle_With_BlockID);
    //Serial.println();

    //seriallogger_string("\r\n");
    //seriallogger_string("Inst BlockID FILE NAME: ");
    seriallogger_string("Inst BlockID FILE NAME: " + Inst_Data_FIle_With_BlockID);
    //seriallogger_string("\r\n");
   
    WritePostDataIntoBlockIDFile(Inst_Data_FIle_With_BlockID, FinalInst_str);//88888888
    //ReadFromFile(Inst_Data_FIle_With_BlockID);
}
/*CREATE AND WRITE INST DATA FILE*/

/*CREATE AND WRITE LOAD DATA FILE*/
void CreateLoadDataFile(int Load_ChoppedByteCount, int arg_loadday, int arg_BlockID)
{
    char temp[5]={0};
    String Load_Data_FIle_With_BlockID = "";
    String FinalLoad_str = "$";
    FinalLoad_str += global_NodeID;
    FinalLoad_str += "_";
    FinalLoad_str += (String)PhaseType;
    FinalLoad_str += "_";
    FinalLoad_str += "L";
    FinalLoad_str += "_";
    FinalLoad_str += MeterSerialNo_Final;
    FinalLoad_str += "_";
    for(int i = 0; i < Load_ChoppedByteCount; i++)
    {
      FinalLoad_str += (uint8_t)Chopped_Load_DataBuffer[i];
      FinalLoad_str += " ";
    }
    FinalLoad_str.trim();
    FinalLoad_str += "$";
    //Serial.println();
    //Serial.println("\r\nFINAL LOAD STRING\r\n");
    //Serial.println(FinalLoad_str);
    //Serial.println();

    //seriallogger_string("FINAL LOAD STRING");
    seriallogger_string(FinalLoad_str);


    Load_Data_FIle_With_BlockID = "/meterreadingdata"; //13-04-2022
    Load_Data_FIle_With_BlockID += "/";

    
    
    //Load_Data_FIle_With_BlockID += temp_Char_Array;//BlockID    //(String)arg_BlockID;  //
    sprintf(temp, "%02s", (String)arg_BlockID/*day*/);
    Load_Data_FIle_With_BlockID += temp;


    
    /*//Serial.print("\r\nBlockID: ");
    //Serial.println(Inst_Data_FIle_With_BlockID);*/
    Load_Data_FIle_With_BlockID += "_";
    
    /*Load_Data_FIle_With_BlockID += (String)PhaseType;
    Load_Data_FIle_With_BlockID += "_";
    Load_Data_FIle_With_BlockID += (String)MeterCategoryType;
    Load_Data_FIle_With_BlockID += "_";
    Load_Data_FIle_With_BlockID += MeterSerialNo_Final;*/

    sprintf(temp, "%02s", (String)arg_loadday/*day*/);
    Load_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%02s", (String)month);
    Load_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%04s", (String)year);
    Load_Data_FIle_With_BlockID += temp;
    Load_Data_FIle_With_BlockID += "_";
    sprintf(temp, "%02s", (String)hours);
    Load_Data_FIle_With_BlockID += temp;
    sprintf(temp, "%02s", (String)minutes);
    Load_Data_FIle_With_BlockID += temp;

    
    Load_Data_FIle_With_BlockID += "_";
    Load_Data_FIle_With_BlockID += "L.txt";
    //Serial.println();
    //Serial.print("\r\nLoad BlockID FILE NAME: ");
    //Serial.println(Load_Data_FIle_With_BlockID);
    //Serial.println();

    seriallogger_string("Load BlockID FILE NAME: " + Load_Data_FIle_With_BlockID);
    //seriallogger_string(Load_Data_FIle_With_BlockID);
    //seriallogger_string("\r\n");
    WritePostDataIntoBlockIDFile(Load_Data_FIle_With_BlockID, FinalLoad_str);
    //ReadFromFile(Load_Data_FIle_With_BlockID);
}
/*CREATE AND WRITE LOAD DATA FILE*/

/*UPDATE BLOCK ID FILE*/
void UpdateBlockID(String FileName)
{
    ReadFromFile(FileName);  
    for(int blockindex = 0; blockindex < (sizeof(BlockIDs)/12); blockindex++)
    {
      String BlockID = temp_Char_Array;
      ////Serial.println(BlockID);
      if( BlockIDs_Buffer[blockindex].indexOf(BlockID) > 0 )
      {
        String BlockID_Status = BlockIDs_Buffer[blockindex].substring(0, 2);//00|23
        //Serial.print("BlockID_Status: ");
        //Serial.println(BlockID_Status);
        //Serial.println();
        /*seriallogger_string("\r\nBlockID_Status: ");
        seriallogger_string(BlockID_Status);
        seriallogger_string("\r\n");*/
        int int_BlockID_Status = BlockID_Status.toInt();
        int_BlockID_Status =  1;//SET
        //Serial.print(int_BlockID_Status);
        //Serial.println();
        /*seriallogger_string((String)int_BlockID_Status);
        seriallogger_string("\r\n");*/
        char temp_array[4];
        sprintf(temp_array, "%02s", (String)int_BlockID_Status);
        BlockIDs_Buffer[blockindex] = temp_array;
        BlockIDs_Buffer[blockindex] += "|";
        BlockIDs_Buffer[blockindex] += BlockID;
        //Serial.print(BlockIDs_Buffer[blockindex]);
        /*seriallogger_string((String)BlockIDs_Buffer[blockindex]);*/
        //seriallogger_string("\r\n");
        WriteIntoBlockIDFile(FileName, BlockIDs_Buffer, (sizeof(BlockIDs)/12));
        ReadFromFile(FileName);
        for(int i = 0; i < (sizeof(BlockIDs)/12); i++)
        {
          //Serial.println(BlockIDs_Buffer[i]);
          seriallogger_string((String)BlockIDs_Buffer[i]);
        }
        break;
      }
    }
}

/*READ INST PROFILE*/
void ReadInstData()
{
    int total_no_req = 0;
    if(PhaseType == SINGLE_PHASE)
      total_no_req = SINGLE_PH_PARAM_COUNT + ASSC_REQ_COUNT;
    else
      total_no_req = THREE_PH_PARAM_COUNT + ASSC_REQ_COUNT;      
    char INST_REQframeptr[total_no_req][MAX_SIZE] = {0};
    //Serial.println("Instantaneous Data Read Started...");
    //seriallogger_string("Instantaneous Data Read Started...");
    int Inst_ChoppedByteCount = InstReqFrame(&INST_REQframeptr[0], PhaseType);

    if(Inst_ChoppedByteCount == 0)
      return;

    //INITIALIZE METER SERIAL NUMBER
    //Serial.println();//30-03-2022
    //seriallogger_string("\r\n");
    //Serial.print("METER SERIAL NUMBER: ");//30-03-2022
    //seriallogger_string("METER SERIAL NUMBER: ");    
    MeterSerialNo_Final.trim();
    //MeterSerialNo_Final = (String)ParsedMeterSerialNo;//30-03-2022
    //Serial.println(MeterSerialNo_Final);//30-03-2022
    seriallogger_string("METER SERIAL NUMBER: " + MeterSerialNo_Final);
    //Serial.println();//30-03-2022
    //seriallogger_string("\r\n");
    ////Serial.println(Inst_ChoppedByteCount);//30-03-2022
    //Serial.println("Instantaneous Data Read Completed.");
    //seriallogger_string("Instantaneous Data Read Completed.");

    if(MeterSerialNo_Final.length() == 0)//IF METER SERIAL NUMBER IS NOT AVAILABLE DONT PROCEED FURTHER
      return;
   
    //FILE READ WRITE OPERATIONS START
    /*int FileContentSize = (sizeof (INST_REQframeptr) / sizeof (INST_REQframeptr[0]));
    WriteIntoFile("/INST_REQframeptr.txt", INST_REQframeptr, FileContentSize);
    ReadFromFile("/INST_REQframeptr.txt");*/

    Get_Scalar_Flag = true;//14-04-2022
    //memset(INST_REQframeptr, 0, sizeof(INST_REQframeptr));
    for(int j = 0; j < MAX_SIZE; j++)
    {
        for(int i = 0; i < total_no_req; i++)
        {  
            INST_REQframeptr[i][j] = 0;
        }
    }
    //delay(2000);
    int Inst_Scalar_ChoppedByteCount = InstReqFrame(&INST_REQframeptr[0], PhaseType);//14-04-2022

    if(Inst_Scalar_ChoppedByteCount == 0)
      return;

    
    CreateInstDataFile(Inst_ChoppedByteCount, Inst_Scalar_ChoppedByteCount);
    CheckForMeterChange(MeterSerialNo_Final);
}
/*READ INST PROFILE*/

void ReadMissingLoadProfileBlock()
{
  char local_temp_Char_Array[4] = {0};
  int temp_hour = hours;
  int temp_day = 0;
  /*if(rtc.getAmPm(true).equals("pm") && rtc.getHour() != 12)  
    temp_hour = rtc.getHour() + 12;
  else
    temp_hour = rtc.getHour();*/

    //19-04-2022
//  String fileName = "";
//  fileName = "/";
//  fileName += (String)day;//(String)rtc.getDay();  
//  fileName += "-";
//  fileName += (String)month;//(String)(rtc.getMonth()+1);
//  fileName += "-";
//  fileName += (String)year;//(String)rtc.getYear();
//  fileName += ".txt";

  String fileName, temp_fileName; 
  Dir dir = LittleFS.openDir("/BlockIDStatusFiles");

  while (dir.next()) 
  {
      temp_fileName = ""; fileName = "";
      
      temp_fileName += dir.fileName(); 
      fileName = "/BlockIDStatusFiles";
      fileName += "/";
      fileName += temp_fileName;

      temp_day = temp_fileName.substring(0, 2).toInt();

      //seriallogger_string("temp_day");
      //seriallogger_string((String)temp_day);

  
      ReadFromFile(fileName);
      
      for(int blockindex = 0; blockindex < (sizeof(BlockIDs)/12); blockindex++)
      {
        String BlockID_Status = BlockIDs_Buffer[blockindex].substring(0, 2);//00|23
        //Serial.print("\r\n\r\nBlockID_Status: ");
        //Serial.println(BlockID_Status);
    
        /*seriallogger_string("\r\n\r\nBlockID_Status: ");
        seriallogger_string(BlockID_Status);*/
       
        //Serial.println();
        int int_BlockID_Status = BlockID_Status.toInt();
        //Serial.print(int_BlockID_Status);
        /*seriallogger_string((String)int_BlockID_Status);*/
        //Serial.println();
    
        if(!int_BlockID_Status)
        {
          String BlockID_No = BlockIDs_Buffer[blockindex].substring(3);//00|23
    
          //Serial.println(BlockID_No);
          /*seriallogger_string(BlockID_No);*/
         
          //memset(local_temp_Char_Array, 0, sizeof(local_temp_Char_Array));
          memsetbuffer(local_temp_Char_Array, sizeof(local_temp_Char_Array));
          sprintf(local_temp_Char_Array, "%02s", (String)BlockID_No);
    
          //Serial.println(local_temp_Char_Array);
          /*seriallogger_string((String)local_temp_Char_Array);*/
    
          int targetIndex = 0;
          //memset(temp_Char_Array, 0, sizeof(temp_Char_Array));
          memsetbuffer(temp_Char_Array, sizeof(temp_Char_Array));
          for (int x = 0; x < 2; x++)
          {
            temp_Char_Array[targetIndex] = local_temp_Char_Array[x];
            targetIndex++;
          }
          //temp_Char_Array = local_temp_Char_Array;
         
          //Serial.println(local_temp_Char_Array);
          /*seriallogger_string((String)local_temp_Char_Array);*/
          String BlockID = local_temp_Char_Array;
          //Serial.println(BlockID);
          /*seriallogger_string((String)BlockID);*/
          int int_BlockID_No = BlockID_No.toInt();
    
          /*if(int_BlockID_No >= temp_hour)
          {
            return;
          }*/


          //seriallogger_string("\r\n\r\n------------------------------");
          seriallogger_string((String)int_BlockID_No + ", " + (String)temp_hour + ", " + (String)temp_day + ", " + (String)day);
          //seriallogger_string((String)temp_hour);
          //seriallogger_string((String)temp_day);
          //seriallogger_string((String)day);
          //seriallogger_string("------------------------------\r\n\r\n");
          
          
          if(((int_BlockID_No < temp_hour) && (temp_day == day)) || (temp_day < day))
          {
            bool data_status_flag = ReadLoadProfileData(int_BlockID_No, minutes/*rtc.getMinute()*/, temp_day/*day*//*rtc.getDay()*/, month/*rtc.getMonth()*/, year/*rtc.getYear()*/);//04-04-2022
            if(data_status_flag)
            {
              int_BlockID_Status = 1;
              char temp_array[4] = {0};
              sprintf(temp_array, "%02s", (String)int_BlockID_Status);
              BlockIDs_Buffer[blockindex] = temp_array;
              BlockIDs_Buffer[blockindex] += "|";
              BlockIDs_Buffer[blockindex] += BlockID;
              //Serial.println(BlockIDs_Buffer[blockindex]);
              /*seriallogger_string((String)BlockIDs_Buffer[blockindex]);*/
       
              //Serial.println("fileName: ");
              //Serial.print(fileName);
      
              /*seriallogger_string("\r\nfileName: ");
              seriallogger_string(fileName);*/
            }
          }
          else
          {
            break;
          }
        }
      }
      WriteIntoBlockIDFile(fileName, BlockIDs_Buffer, (sizeof(BlockIDs)/12));
      ReadFromFile(fileName);
      //Serial.println("UPDATED ");
     
      #if 0
      seriallogger_string("UPDATED");
      for(int i = 0; i < (sizeof(BlockIDs)/12); i++)
      {
        //Serial.println(BlockIDs_Buffer[i]);
        seriallogger_string((String)BlockIDs_Buffer[i]);
      }
      #endif 

    }
}


void RTC()
{  
  // put your main code here, to run repeatedly:
  timeNow = millis()/1000; // the number of milliseconds that have passed since boot
 
  seconds = (/*seconds +*/ (timeNow - timeLast));//the number of seconds that have passed since the last time 60 seconds was reached.
  //ActualSeconds = seconds;
 
  if (seconds >= 60) {
    timeLast = timeNow;
    //ActualSeconds = 0;
    minutes = minutes + 1;
 
    /*//Serial.print("The time is:           ");
    //Serial.print(days);
    //Serial.print(":");
    //Serial.print(hours);
    //Serial.print(":");
    //Serial.print(minutes);
    //Serial.print(":");
    //Serial.println(seconds); */
   
  }
 
  //if one minute has passed, start counting milliseconds from zero again and add one minute to the clock.
 
  if (minutes >= 60){
    minutes = 0;
    hours = hours + 1;
  }
 
  // if one hour has passed, start counting minutes from zero and add one hour to the clock
 
  if (hours == 24){
    hours = 0;
    days = days + 1;
    }
 
    //if 24 hours have passed , add one day
 
  if (hours ==(24 - startingHour) && correctedToday == 0){
    delay(dailyErrorFast*1000);
    seconds = seconds + dailyErrorBehind;
    correctedToday = 1;
  }
 
  //every time 24 hours have passed since the initial starting time and it has not been reset this day before, add milliseconds or delay the progran with some milliseconds.
  //Change these varialbes according to the error of your board.
  // The only way to find out how far off your boards internal clock is, is by uploading this sketch at exactly the same time as the real time, letting it run for a few days
  // and then determine how many seconds slow/fast your boards internal clock is on a daily average. (24 hours).
 
  if (hours == 24 - startingHour + 2) {
    correctedToday = 0;
  }
 
  //let the sketch know that a new day has started for what concerns correction, if this line was not here the arduiono
  // would continue to correct for an entire hour that is 24 - startingHour.
 
    /*//Serial.print("The time is:           ");
    //Serial.print(days);
    //Serial.print(":");
    //Serial.print(hours);
    //Serial.print(":");
    //Serial.print(minutes);
    //Serial.print(":");
    //Serial.println(seconds);*/


    /*seriallogger_string("\r\nThe date is:  ");
    seriallogger_string((String)day);
    seriallogger_string("-");
    seriallogger_string((String)month);
    seriallogger_string("-");
    seriallogger_string((String)year);
    seriallogger_string("\r\n\r\n");
   
    seriallogger_string("\r\nThe time is:  ");
    seriallogger_string((String)hours);
    seriallogger_string(":");
    seriallogger_string((String)minutes);
    seriallogger_string(":");
    seriallogger_string((String)seconds);
    seriallogger_string("\r\n\r\n");*/
}


void handlelogs()
{
  //server.send(200, "text/html", "5055534846494C45204E4F542050524553454E54");
  //
  //  //Serial.println(logger_file);

  File readpushfile = LittleFS.open("/loginfo1.txt", "r");

  if (!readpushfile)
  {
    server.send(200, "text/html", "5055534846494C45204E4F542050524553454E54");
    return;
  }
  else
  {
    size_t  fsizeSent = server.streamFile(readpushfile, "text/plain");
//  //Serial.print("fsizeSent: ");
//  //Serial.println(fsizeSent);setup

    readpushfile.close();
  }

}



void handlefiledata()
{

  if (server.hasArg("filename"))
  {
    String  filename = server.arg("filename");

    //Serial.println(filename);

    File c2 = LittleFS.open("/meterreadingdata/" + filename , "r");
    if (c2) {
      String readbuf;
      readbuf = c2.readString();
      c2.close();
      if (isSpace(readbuf[0])) {  // tests if myChar is a white-space character
        //Serial.print("there is space");
      }
      if (readbuf != 0) {
        server.send(200, "text/html", readbuf);
      }
      else
      {
        server.send(200, "text/html", "File is Empty");
      }
    }//end of c2 check
    else {
      server.send(200, "text/html", "Unable to Open File/No such file");
    }

  }

  else {
    server.send(200, "text/html", "Argument missing");

  }
}




void handlefilelist()
{

  String file_list;
  int fsize=0;
  Dir dir = LittleFS.openDir("/meterreadingdata");
 
    while (dir.next()) {
      file_list += dir.fileName() + ",";
       fsize += dir.fileSize();
      
       
      

    }
    if (file_list != 0) {

      //Serial.println(file_list);
      server.send(200, "text/html", file_list);
    }
    else {
      server.send(200, "text/html", "No file exist");
    }
 Serial.println(fsize);
 
}


void handledeletemeterdata() {

  if (server.hasArg("filename"))
  {
    String  filename = server.arg("filename");

    //Serial.println(filename);

    delay(3000);

    bool is_file_delete_success = LittleFS.remove("/meterreadingdata/" + filename);
    if (is_file_delete_success == true)
    {

      server.send(200, "text/html", "File Delete successful");
    }
    else {
      server.send(200, "text/html", "No such file exists/Unable to Delete");
    }

  }
  else {

    server.send(200, "text/html", "Argument missing");

  }



}



void handledeletefile()
{  
  if (server.hasArg("filename"))
  {
    String  filename = server.arg("filename");

    Serial.println(filename);

    delay(3000);

    bool is_file_delete_success = LittleFS.remove(filename);
    if (is_file_delete_success == true)
    {

      server.send(200, "text/html", "File Delete successful");
    }
    else {
      server.send(200, "text/html", "No such file exists/Unable to Delete");
    }
  }
  else {
    server.send(200, "text/html", "Argument missing");
  }
}

void handlerelayop()
{
  if (server.hasArg("status"))
  {    
    String  relay_position = server.arg("status");
    if (relay_position.equals("0"))
    {
      digitalWrite(RELAY_OFF, HIGH);
      delay( 1000 );
      digitalWrite(RELAY_OFF, LOW);
      delay( 1000 );
      server.send(200, "text/html", "52454C4159204953204F4646");
      WritePostDataIntoBlockIDFile("/RelayStatus/status.txt", "0");
      return ;
    }
    else if (relay_position.equals("1"))    
    {
      digitalWrite(RELAY_ON, HIGH);
      delay( 1000 );
      digitalWrite(RELAY_ON, LOW);
      delay( 1000 );
      server.send(200, "text/html", "52454C4159204953204F4E");
      WritePostDataIntoBlockIDFile("/RelayStatus/status.txt", "1");
      return ;
    }
    else
    {
      server.send(404, "text/html", "52454C4159204953204F4E");
      WritePostDataIntoBlockIDFile("/RelayStatus/status.txt", "RELAY STATUS NOT FOUND");
      return;
    }
  }  
}

 




void seriallogger(unsigned char loginfo){
File readfile = LittleFS.open("/loginfo1.txt", "a");
////Serial.println("logging data");
////Serial.print(loginfo);

  if(readfile){
    /*readfile.print(loginfo);
    readfile.print(' ');*/
    if(loginfo == '\r' || loginfo == '\n')
      readfile.println();
    else
    {
      readfile.print(loginfo, HEX);
      readfile.print(' ');
    }
   
//    //Serial.print("file reading ");
  }
  readfile.close();
}

void seriallogger_string(String loginfo){
File readfile = LittleFS.open("/loginfo1.txt", "a");
////Serial.println("logging data");
////Serial.print(loginfo);

  if(readfile){
    /*readfile.print(loginfo);
    readfile.print(' ');*/
   
    readfile.println(loginfo);
   
//    //Serial.print("file reading ");
  }
  readfile.close();
}

void memsetbuffer(char *buffer_name , uint32_t len)
{
  uint32_t i =0 ;
 
  for( i = 0 ; i < len ; i++ )
  {
    buffer_name[i] = 0;  
  }
}

void CreateBlockIDFIle(String FileName)
{
  //Serial.println("\r\nTOP\r\n");
  if(!LittleFS.exists(FileName))
  {
    //seriallogger_string("INSIDE");
    //Serial.println("\r\nCREATING BLOCK STATUS LOG FILE NOW\r\n");
    seriallogger_string("CREATING BLOCK STATUS LOG FILE NOW");
    WriteIntoBlockIDFile(FileName, BlockIDs, (sizeof(BlockIDs)/12));
    //ReadFromFile(FileName);  
    //for(int i = 0; i < (sizeof(BlockIDs)/12); i++)
    //{
    //  seriallogger_string(BlockIDs_Buffer[i]);
    //}
  }
}



void CheckForMeterChange(String arg_MSN)
{
  String p;
  String fs_MSN_path = "";
  String BlockIDsFileName = "";
  fs_MSN_path = "/MeterSlNo";
  fs_MSN_path += "/";
  fs_MSN_path += "MSN.txt";

  arg_MSN.trim();
  //seriallogger_string("START");
  //seriallogger_string(arg_MSN);
  
  String FromFileMSN = ReadMSNFromFile(fs_MSN_path);
  FromFileMSN.trim();

  
  //seriallogger_string(FromFileMSN);

  
  if(FromFileMSN.equals(arg_MSN))
  {       
    seriallogger_string("NO METER CHANGE");
  } 
  else if(FromFileMSN == "NILL")
  {
    WritePostDataIntoBlockIDFile(fs_MSN_path, arg_MSN);
    seriallogger_string("MSN FILE CREATED");
  }
  else
  {    
    //REMOVE ALL OLD FILES IN THE MEMORY WHEN METER GOT CHANGED
    DeleteFilesInDrectory("/meterreadingdata");
    DeleteFilesInDrectory("/MeterSlNo");
    DeleteFilesInDrectory("/BlockIDStatusFiles");
    DeleteFilesInDrectory("/RelayStatus");
    LittleFS.remove("/loginfo1.txt");
    LittleFS.remove("/InstDataStatus.txt");

    WritePostDataIntoBlockIDFile(fs_MSN_path, arg_MSN);
    seriallogger_string("NEW METER DETECTED");

    BlockIDsFileName = "";
    BlockIDsFileName = "/BlockIDStatusFiles";
    BlockIDsFileName += "/";
    BlockIDsFileName += (String)day;//(String)rtc.getDay();  
    BlockIDsFileName += "-";
    BlockIDsFileName += (String)month/*(rtc.getMonth()+1)*/;
    BlockIDsFileName += "-";
    BlockIDsFileName += (String)year/*rtc.getYear()*/;
    BlockIDsFileName += ".txt";                                                                                        //LittleFS.remove(BlockIDsFileName);          //TO BE REMOVED
    CreateBlockIDFIle(BlockIDsFileName);//19-04-2022
  }
}

/*READ MSN FROM FILE*/
String ReadMSNFromFile(String MSNFileName)
{
  String MSN = "";
  //File file2 = LittleFS.open(ReadFileName);
  File file2 = LittleFS.open(MSNFileName, "r");
 
  if(!file2){
      //Serial.println("Failed to open file for reading");
      seriallogger_string("Failed to open file for reading");
      return "NILL";
  }

  //seriallogger_string(ReadFileName);

  ////Serial.println("File Content: ");

  char bufferc[16];  
  while(file2.available())
  {
      //Serial.write(file2.read());//Original
      
      /*int a = file2.readBytesUntil('\n', bufferc, sizeof(bufferc));      
      bufferc[a] = 0;
      MSN = (String)bufferc;*/

      MSN = file2.readString();
      
  }
  ////Serial.println();
  
  ////Serial.println();
  file2.close();

  return MSN;
}
/*READ MSN FROM FILE*/

void DeleteFilesInDrectory(String DirectoryName)
{
  String temp_fileName = ""; 
  String fileName = "";
  Dir dir = LittleFS.openDir(DirectoryName);

  while (dir.next()) 
  {   temp_fileName = "", fileName = "";
      temp_fileName += dir.fileName(); 
      fileName = DirectoryName;
      fileName += "/";
      fileName += temp_fileName;
      //Serial.println(fileName);
      LittleFS.remove(fileName);
      //Serial.println("DELETED");
      //Serial.println();
  }

}

//CHECK LOG FILE SIZE
void CheckLogFileSize()
{
  int filesize={0};
  File file = LittleFS.open("/loginfo1.txt", "r");
  filesize = file.size();
  file.close();
  //seriallogger_string((String)filesize);
  if(filesize >= 10000)//IF FILE SIZE IS GREATER THAN 10KB, THEN DELETE THE FILE
  {
    LittleFS.remove("/loginfo1.txt");   
    seriallogger_string("LOG FILE DELETED"); 
  }
}


//Check MeterReadingData Files Total Size
void CheckMeterDataFilesSize()
{
  String file_list;
  int fsize=0;
  Dir dir = LittleFS.openDir("/meterreadingdata");
 
  while (dir.next()) 
  {     fsize += dir.fileSize();   

  } 

  if(fsize >= 1000000)//IF TOTAL FILE SIZE OF METER DATA IS GREATER THAN 1MB(10,00,000 Bytes in Appox.), CLEAR ALL FILES.
  {
    DeleteFilesInDrectory("/meterreadingdata");
    seriallogger_string("METER DATA MEMORY IF FULL, CLEARING OLD DATA.");
  }
}

void handleresumereading()
{
  if (server.hasArg("status"))
  {   
    String  resume_status = server.arg("status");   
    if (resume_status.equals("resume"))
    {       
      resume_reading = 1;  
        
      server.send(200, "text/html", "52454C4159204953204F4646");
      return ;
    }
    else
    {
      server.send(404, "text/html", "52454C4159204953204F4E");
      return;
    }
  }   
}


void handlemeterslno()
{     
  String MSN = ReadMSNFromFile("/MeterSlNo/MSN.txt"); 
  if (MSN.length() == 0)
  {
    server.send(200, "text/html", "4D534E204E4F5420464F554E44");
    return;
  }
  else
  {
    server.send(200, "text/html", MSN);
    return;
  }
}

void handlerelaystatus()
{     
  String MSN = ReadMSNFromFile("/RelayStatus/status.txt"); //READING REALY STATUS FROM FILE
  if (MSN.length() == 0)
  {
    server.send(200, "text/html", "RELAY STATUS NOT FOUND");
    return;
  }
  else
  {
    server.send(200, "text/html", MSN);
    return;
  }
}

#if 0
/*TEMP LOAD REQUEST FRAMING 10-05-2022*/
int temp_LoadReqFrame(char fromDateTime[], char ToDateTime[])
{
  char LoadREQframeptr[7][MAX_SIZE];
  int ResByteCount = 0;
  int ChoppedByteCount = 0;
  int i = 0;  
  int arrindex = 0;
  char Load_dis_con=0;
  char MeterDataType = LOAD_PROFILE_DATA;

  SNRMframing();
  hdlc_SendPacket(arrindex,LoadREQframeptr);  

  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  delay(1000);
  SerialRead(arrindex, ResByteCount);
  
  
  arrqframe_index=AARQ_Client_Meter_Reader_Password(/*passwordkey*/);
  char FrameType=INFORMATION_FRAME;
  HdlcWrapperEncoding(FrameType,&AARQFrame[0],arrqframe_index);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);

  ResByteCount = 0;
  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  delay(1000);
  SerialRead(arrindex, ResByteCount);

  //04-04-2022    
  GetSequenceNumber(0);

  DateTimeRange(Fromdate, Todate, fromDateTime, ToDateTime);

  for(i=0;i<4;i++)
  {
    MeterCommandFrame(Fromdate,Todate, MeterDataType);

    //04-04-2022    
    GetSequenceNumber(0);
    
    hdlc_SendPacket(++arrindex,LoadREQframeptr);

    ResByteCount = 0;
    Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
    delay(1000);
    SerialRead(arrindex, ResByteCount);

    /*****************************************************************************************/
    if(ResponseBuffer[arrindex][1] == 0xA8)
    {
      seriallogger_string("SUPERVISORY RESPONSE");
      FrameType=SUPERVISORY_FRAME;
      HdlcWrapperEncoding(FrameType,NULL,0);
      GetSequenceNumber(0);
      hdlc_SendPacket(++arrindex,LoadREQframeptr);

      ResByteCount = 0;
      Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
      delay(1000);
      SerialRead(arrindex, ResByteCount);   
    }
    /*****************************************************************************************/
    
  }

  FrameType=DISCONNECT_FRAME;
  HdlcWrapperEncoding(FrameType,NULL,0);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);

  ResByteCount = 0;
  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  delay(1000);
  SerialRead(arrindex, ResByteCount);
  


/////////////////////////////////////////////////////////////////////////////////////////
/*  Serial.println("*******LOAD FINAL********");
  for(int i=0; i < arrindex; i++)
  {
    for(int j=0; j < (LoadREQframeptr[i][2]+2); j++)
    {
      Serial.print((LoadREQframeptr[i][j]), HEX);
      Serial.print(" ");
    }
    Serial.println();
  }
  Serial.println("*******LOAD FINAL********");

  Serial.println("RESPONSE BUFFER: ");
  for(int i=0; i <= arrindex; i++)
  {
    for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
    {
      Serial.print((ResponseBuffer[i][j]), HEX);
      Serial.print(" ");
    }
    Serial.println();
  }*/

  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  //CHOPPING LOAD REPONSES WILL BE DONE HERE
  ChoppedByteCount = ChopLoadMeterResponse(ResponseBuffer, (arrindex+1));

  //Clearing Response Buffer after parsing data in it
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }
  return ChoppedByteCount;
}
/*TEMP LOAD REQUEST FRAMING 10-05-2022*/
#endif


int temp_LoadReqFrame(char fromDateTime[], char ToDateTime[])
{
  char LoadREQframeptr[7][MAX_SIZE];
  int ResByteCount = 0;
  int ChoppedByteCount = 0;
  int i = 0;  
  int arrindex = 0;
  char Load_dis_con=0;
  char MeterDataType = LOAD_PROFILE_DATA;
  memsetbuffer(AARQFrame, sizeof(AARQFrame));

  SNRMframing();
  hdlc_SendPacket(arrindex,LoadREQframeptr); 

  ResByteCount = 0;
  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  //delay(1000);
  SerialRead(arrindex, ResByteCount);

  //BREAK METER READING OF NO RESPONSE FROM METER
  if(ResponseBuffer[arrindex][0] != 0x7E || ResponseBuffer[arrindex][2] == 0 || WiFi.softAPgetStationNum() > 0)
  {
      int val = WiFi.softAPgetStationNum();
       
      seriallogger_string("exiting loop because wifi status is more " + String(val));

      if(val > 0)
        is_reading_interrupted = 1;
      
      Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

      return 0;
  }
   
  arrqframe_index=AARQ_Client_Meter_Reader_Password(/*passwordkey*/);
  char FrameType=INFORMATION_FRAME;
  HdlcWrapperEncoding(FrameType,&AARQFrame[0],arrqframe_index);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);

  ResByteCount = 0;
  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  //delay(1000);
  SerialRead(arrindex, ResByteCount);

  //BREAK METER READING OF NO RESPONSE FROM METER
  if(ResponseBuffer[arrindex][0] != 0x7E || ResponseBuffer[arrindex][2] == 0 || WiFi.softAPgetStationNum() > 0)
  {
      int val = WiFi.softAPgetStationNum();
       
      seriallogger_string("exiting loop because wifi status is more " + String(val));

      if(val > 0)
        is_reading_interrupted = 1;
      
      Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

      return 0;
  }

  //04-04-2022    
  GetSequenceNumber(0);

  DateTimeRange(Fromdate, Todate, fromDateTime, ToDateTime);

  for(i=0;i<4;i++)
  {
    MeterCommandFrame(Fromdate,Todate, MeterDataType);

    //04-04-2022    
    GetSequenceNumber(0);

    hdlc_SendPacket(++arrindex,LoadREQframeptr);

    ResByteCount = 0;
    Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
    //delay(1000);
    SerialRead(arrindex, ResByteCount);
  
    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[arrindex][0] != 0x7E || ResponseBuffer[arrindex][2] == 0 || WiFi.softAPgetStationNum() > 0)
    {
        int val = WiFi.softAPgetStationNum();
         
        seriallogger_string("exiting loop because wifi status is more " + String(val));
  
        if(val > 0)
          is_reading_interrupted = 1;
        
        Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());
  
        return 0;
    }

    /*****************************************************************************************/
    if(ResponseBuffer[arrindex][1] == 0xA8)
    {
      seriallogger_string("SUPERVISORY RESPONSE");
      FrameType=SUPERVISORY_FRAME;
      HdlcWrapperEncoding(FrameType,NULL,0);
      GetSequenceNumber(0);
      hdlc_SendPacket(++arrindex,LoadREQframeptr);

      ResByteCount = 0;
      Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
      //delay(1000);
      SerialRead(arrindex, ResByteCount);  

      //BREAK METER READING OF NO RESPONSE FROM METER
      if(ResponseBuffer[arrindex][0] != 0x7E || ResponseBuffer[arrindex][2] == 0 || WiFi.softAPgetStationNum() > 0)
      {
          int val = WiFi.softAPgetStationNum();
           
          seriallogger_string("exiting loop because wifi status is more " + String(val));
    
          if(val > 0)
            is_reading_interrupted = 1;
          
          Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());
    
          return 0;
      }
    }
    /*****************************************************************************************/   
  }

  FrameType=DISCONNECT_FRAME;
  HdlcWrapperEncoding(FrameType,NULL,0);
  hdlc_SendPacket(++arrindex,LoadREQframeptr);

  ResByteCount = 0;
  Serial.write( &LoadREQframeptr[arrindex][0], (LoadREQframeptr[arrindex][2]+2) );
  //delay(1000);
  SerialRead(arrindex, ResByteCount);

  //BREAK METER READING OF NO RESPONSE FROM METER
  if(ResponseBuffer[arrindex][0] != 0x7E || ResponseBuffer[arrindex][2] == 0 || WiFi.softAPgetStationNum() > 0)
  {
    int val = WiFi.softAPgetStationNum();
     
    seriallogger_string("exiting loop because wifi status is more " + String(val));

    if(val > 0)
      is_reading_interrupted = 1;
    
    Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

    return 0;
  }
  
  ObiscodeIndex = 0;
  g_RRR = 0;
  g_SSS = 0;

  /*//Serial.println("*******LOAD FINAL********");
  for(int i=0; i < 7; i++)
  {
    for(int j=0; j < (LoadREQframeptr[i][2]+2); j++)
    {
      //Serial.print((LoadREQframeptr[i][j]), HEX);
      //Serial.print(" ");
    }
    //Serial.println();
  }
  //Serial.println("*******LOAD FINAL********");*/

#if 0
  /*Read Send and Read Response from meter here. Response will be added into ResponseBuffer Global buffer.*/
  for(int reqIndex = 0; reqIndex < 7; reqIndex++)
  {
    int ResByteCount = 0;
    Serial.write( &LoadREQframeptr[reqIndex][0], (LoadREQframeptr[reqIndex][2]+2) );
    delay(1000);
    SerialRead(reqIndex, ResByteCount);

    //BREAK METER READING OF NO RESPONSE FROM METER
    if(ResponseBuffer[reqIndex][0] != 0x7E || ResponseBuffer[reqIndex][2] == 0 || WiFi.softAPgetStationNum() > 0)
    {
        int val = WiFi.softAPgetStationNum();
         
        seriallogger_string("exiting loop because wifi status is more " + String(val));

        if(val > 0)
          is_reading_interrupted = 1;
        
        Serial.printf("number of devices %d \n",WiFi.softAPgetStationNum());

        return 0;
    }
      
    //seriallogger('\n');
    //seriallogger('\n');
  }
#endif

seriallogger_string("RESPONSE BUFFER: ");
 for(int i=0; i < arrindex; i++)
 {
   for(int j=0; j < (ResponseBuffer[i][2]+2); j++)
   {
     seriallogger((ResponseBuffer[i][j]));
     //seriallogger(' ');
   }
   seriallogger('\n');
 }

  //CHOPPING LOAD REPONSES WILL BE DONE HERE
  ChoppedByteCount = ChopLoadMeterResponse(ResponseBuffer, (arrindex + 1));

  //Clearing Response Buffer after parsing data in it
  //memset(ResponseBuffer,0,sizeof(ResponseBuffer));  
  for(int j = 0; j < MAX_SIZE_RESPONSE_BUFFER; j++)
  {
      for(int i = 0; i < 31; i++)
      {  
          ResponseBuffer[i][j] = 0;
      }
  }
  return ChoppedByteCount;
}


void CheckForNodeID()
{
  File file = LittleFS.open("/NodeID/NodeID.txt", "r");
  if (!file)
  {   
      Serial.println("\r\nConfigure Node ID: ");
      while(Serial.available()>=0)
      {     
        String nodeid="";          
        if(Serial.available())
        {
       
          nodeid = Serial.readString();
          Serial.println("Entered Node ID is: " + nodeid);
//          gatewayid.toCharArray(gatewayid1,20);
   
          //if (strstr((char*)nodeid, (char*)"NSTG"))
          Serial.println((String)(nodeid.length()));
          
          if((nodeid.indexOf("NSTG") >= 0) && nodeid.length() == 12)
          {
            //Serial.print("Valid Node ID: " + nodeid);
            WritePostDataIntoBlockIDFile("/NodeID/NodeID.txt", nodeid);
            Serial.println("Node ID Configured Successfully");
            global_NodeID = ReadMSNFromFile("/NodeID/NodeID.txt"); 
            break;
          } 
          else 
          {
            Serial.println("Enter valid Node ID: " + nodeid);
          } 
        }
      }
  }   
  else 
  {
    //read node id from file and assign it to a variable  
    global_NodeID = ReadMSNFromFile("/NodeID/NodeID.txt");     
  }
}



void Set_Default_RTC()
{
  year = 2022;
  month = 01;
  day = 06;
  hours = 10;
  minutes = 59;
  seconds = 00;
}
 bool CheckForInstDataStatus()
 {
    char temp[5] = {0};
    String infile_status = ReadMSNFromFile("/InstDataStatus.txt");
    if(infile_status == "NILL")
    {
      seriallogger_string("INST DATA FILE NOT EXISTS");
      return false;
    }
    
    String current_status = "";
    sprintf(temp, "%02s", (String)hours);
    current_status += temp;
    current_status += "_";
    sprintf(temp, "%02s", (String)day);
    current_status += temp;
    sprintf(temp, "%02s", (String)month);
    current_status += temp;
    sprintf(temp, "%04s", (String)year);
    current_status += temp;
    current_status += "_";

    seriallogger_string("infile_status: " + infile_status);
    seriallogger_string("current_status: " + current_status);
    
    if((infile_status.indexOf(current_status) >= 0) && (infile_status.indexOf("_I.txt") >= 0))//IF FILE NAME MATCHES
    {
      seriallogger_string("INST DATA FLAG ALREADY READ");
      return true;
    }
    else
    {
      seriallogger_string("INST DATA FLAG NOT SET");
      return false;
    }
 }


/*WRITE POST DATA INTO BLOCK ID FILE*///30-03-2022
void WriteIntoFile(String WriteFileName, String FileContent)
{
  /*if (!LittleFS.begin()) {
    //Serial.println("An Error has occurred while mounting LittleFS");
    seriallogger_string("An Error has occurred while mounting LittleFS");
    return;
  }*/

  if(FileContent.length() <= 0)
    return;

  //IF EXISTS, REMOVE THE FILE 13-04-2022
  if(LittleFS.exists(WriteFileName))
  {
    LittleFS.remove(WriteFileName);
  }
 
  File file = LittleFS.open(WriteFileName, "w");

  ////Serial.println(WriteFileName);
  if (!file) {
    //Serial.println("There was an error opening the file for writing");
    seriallogger_string("There was an error opening the file for writing");
    return;
  }    
  //file.println(FileContent);
   
  if (file.println(FileContent)) {
    //Serial.println("File was written");
    seriallogger_string("File was written");    
  } else {
    //Serial.println("File write failed");
    seriallogger_string("File write failed");
  } 
  file.close();
}
/*WRITE POST DATA INTO BLOCK ID FILE*/

/*SSID ENCRYPTION CODE STARTS FROM HERE*/
String password_generator(char* ssid_from_file){

  byte enc_iv[N_BLOCK] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

    memset( ssidbuff , 0 , 20 );

    strcpy(ssidbuff,ssid_from_file);

  aes_init();

  aesLib.set_paddingmode(paddingMode::Array);

  char b64in[16] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

  char b64out[base64_enc_len(sizeof(aes_iv))];
  base64_encode(b64out, b64in, 16);

  char b64enc[base64_enc_len(10)];
  base64_encode(b64enc, (char*) "0123456789", 10);

  char b64dec[ base64_dec_len(b64enc, sizeof(b64enc))];
  base64_decode(b64dec, b64enc, sizeof(b64enc));

  String encrypted = encrypt(ssidbuff, strlen(ssidbuff), enc_iv);
  //Serial.println(encrypted);

  for (unsigned int i = 0 ; i < encrypted.length() ; i++ )
  {
    passwordbuff[i] = encrypted[i];
  }



  ////////////////////////////////////////////////////////////////////////////////////////

  // Serial.println("CONFIGURING ACCESS POINT...");
  // Serial.printf("WIFI SSID = %s \r\n", ssidbuff);
 // Serial.printf("WIFI PASSWORD = %s \r\n", passwordbuff);



  return passwordbuff;

}



void aes_init() {
  //Serial.println("gen_iv()");
  aesLib.gen_iv(aes_iv);

  //Serial.println(strdup(plaintext.c_str()));
  //  Serial.println("encrypt()");
  // Serial.println(encrypt(strdup(plaintext.c_str()), (plaintext.length()), aes_iv));
}

String encrypt(char * msg, uint16_t msgLen, byte iv[])
{
  int cipherlength = aesLib.get_cipher64_length(msgLen);
  char encrypted[cipherlength]; // AHA! needs to be large, 2x is not enough
  aesLib.encrypt64(msg, msgLen, encrypted, aes_key, sizeof(aes_key), iv);
  // Serial.print("encrypted = "); Serial.println(encrypted);
  return String(encrypted);
}

String decrypt(char * msg, uint16_t msgLen, byte iv[])
{
  char decrypted[msgLen];
  aesLib.decrypt64(msg, msgLen, decrypted, aes_key, sizeof(aes_key), iv);
  return String(decrypted);
}
/*SSID ENCRYPTION CODE ENDS   FROM HERE*/



String node_serialization(int build_id)
{
  File file = LittleFS.open("/NodeID/NodeID.txt", "r");

  String mainURL ="http://172.104.244.42:9838/getssidinfo?buildid=" + String(build_id);

String payload;


  if (!file)
  {   
      Serial.println("\r\nConfigure Node ID: ");

      
       WiFi.begin("Airtel_9986025401", "air72052");

      while (WiFi.status() != WL_CONNECTED) {  //Wait for the WiFI connection completion

      delay(500);
        Serial.println("Waiting for connection");


      }

        if ( WiFi.status() == WL_CONNECTED) {

    WiFiClient client;

    HTTPClient http;

    Serial.print("[HTTP] begin...\n");
    if (http.begin(client, mainURL)) {  // HTTP
      Serial.print("[HTTP] GET...\n");
  
      // start connection and send HTTP header
      int httpCode = http.GET();

      // httpCode will be negative on error
      if (httpCode > 0) {
        // HTTP header has been send and Server response header has been handled
        Serial.printf("[HTTP] GET... code: %d\n", httpCode);

        // file found at server
        if (httpCode == HTTP_CODE_OK || httpCode == HTTP_CODE_MOVED_PERMANENTLY) {
           payload = http.getString();
          Serial.println(payload);
        }
      } else {
        Serial.printf("[HTTP] GET... failed, error: %s\n", http.errorToString(httpCode).c_str());
      }

      http.end();
    } else {
      Serial.printf("[HTTP} Unable to connect\n");
    }
  }




          Serial.println("length is " + String(payload.length()));

          
          if((payload.indexOf("NSTG") >= 0) && payload.length() == 10)
          {
           
            

            //Serial.print("Valid Node ID: " + nodeid);
            WritePostDataIntoBlockIDFile("/NodeID/NodeID.txt", payload);
            Serial.println("Node ID Configured Successfully");
            global_NodeID = ReadMSNFromFile("/NodeID/NodeID.txt"); 

            digitalWrite(RELAY_OFF, HIGH);
            delay( 1000 );
            digitalWrite(RELAY_OFF, LOW);
            delay( 2000 );

            digitalWrite(RELAY_ON, HIGH);
            delay( 1000 );
            digitalWrite(RELAY_ON, LOW);
            delay( 1000 );
            WritePostDataIntoBlockIDFile("/RelayStatus/status.txt", "1");

            
          } 
          else{
            Serial.println("filewriting failed");

          }
         
      }
     
  else 
  {
    //read node id from file and assign it to a variable  
    global_NodeID = ReadMSNFromFile("/NodeID/NodeID.txt");    
    Serial.println("Global node id is " + global_NodeID);

  }




  return "ok";
}

