#include "esp_wifi.h"
#include <WiFi.h>
//#define LED 2
// #include <HTTPClient.h>

/*const char * ssid = "INFINITUMl7lz";
const char * password = "c67e45f4bf";

String GOOGLE_SCRIPT_ID = "AKfycbwHgRdWDFatwJuhERETDHaTk7uLJliDxbLaRcFtC3TwL-ExPa3Mipm5vqrHyeyfFZ0s"; 
//https://script.google.com/macros/s/AKfycbwHgRdWDFatwJuhERETDHaTk7uLJliDxbLaRcFtC3TwL-ExPa3Mipm5vqrHyeyfFZ0s/exec

const int sendInterval = 5000;

const char * root_ca=\
"-----BEGIN CERTIFICATE-----\n" \
"MIIDujCCAqKgAwIBAgILBAAAAAABD4Ym5g0wDQYJKoZIhvcNAQEFBQAwTDEgMB4G\n" \
"A1UECxMXR2xvYmFsU2lnbiBSb290IENBIC0gUjIxEzARBgNVBAoTCkdsb2JhbFNp\n" \
"Z24xEzARBgNVBAMTCkdsb2JhbFNpZ24wHhcNMDYxMjE1MDgwMDAwWhcNMjExMjE1\n" \
"MDgwMDAwWjBMMSAwHgYDVQQLExdHbG9iYWxTaWduIFJvb3QgQ0EgLSBSMjETMBEG\n" \
"A1UEChMKR2xvYmFsU2lnbjETMBEGA1UEAxMKR2xvYmFsU2lnbjCCASIwDQYJKoZI\n" \
"hvcNAQEBBQADggEPADCCAQoCggEBAKbPJA6+Lm8omUVCxKs+IVSbC9N/hHD6ErPL\n" \
"v4dfxn+G07IwXNb9rfF73OX4YJYJkhD10FPe+3t+c4isUoh7SqbKSaZeqKeMWhG8\n" \
"eoLrvozps6yWJQeXSpkqBy+0Hne/ig+1AnwblrjFuTosvNYSuetZfeLQBoZfXklq\n" \
"tTleiDTsvHgMCJiEbKjNS7SgfQx5TfC4LcshytVsW33hoCmEofnTlEnLJGKRILzd\n" \
"C9XZzPnqJworc5HGnRusyMvo4KD0L5CLTfuwNhv2GXqF4G3yYROIXJ/gkwpRl4pa\n" \
"zq+r1feqCapgvdzZX99yqWATXgAByUr6P6TqBwMhAo6CygPCm48CAwEAAaOBnDCB\n" \
"mTAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUm+IH\n" \
"V2ccHsBqBt5ZtJot39wZhi4wNgYDVR0fBC8wLTAroCmgJ4YlaHR0cDovL2NybC5n\n" \
"bG9iYWxzaWduLm5ldC9yb290LXIyLmNybDAfBgNVHSMEGDAWgBSb4gdXZxwewGoG\n" \
"3lm0mi3f3BmGLjANBgkqhkiG9w0BAQUFAAOCAQEAmYFThxxol4aR7OBKuEQLq4Gs\n" \
"J0/WwbgcQ3izDJr86iw8bmEbTUsp9Z8FHSbBuOmDAGJFtqkIk7mpM0sYmsL4h4hO\n" \
"291xNBrBVNpGP+DTKqttVCL1OmLNIG+6KYnX3ZHu01yiPqFbQfXf5WRDLenVOavS\n" \
"ot+3i9DAgBkcRcAtjOj4LaR0VknFBbVPFd5uRHg5h6h+u/N5GJG79G+dwfCMNYxd\n" \
"AfvDbbnvRG15RjF+Cv6pgsH/76tuIMRQyV+dTZsXjAzlAcmgQWpzU/qlULRuJQ/7\n" \
"TBj0/VLZjmmx6BEP3ojY+x1J96relc8geMJgEtslQIxq/H5COEBkEveegeGTLg==\n" \
"-----END CERTIFICATE-----\n";


WiFiClientSecure client;*/


bool debugMode = false;
String macList[200][3]; //macList stores MAC, timer & channel for up to 200 MACs
String macList2[10][2] = {  
  {"Homero","66:8A:BA:5E:8D:67"},
  {"Javz","E6:27:AD:B6:1E:3A"},
  {"Adri","8C:7A:3D:DE:CF:F9"}
};
int maxMacs  =  sizeof macList  / sizeof macList[0];
int maxMacs2 =  sizeof macList2 / sizeof macList2[0];

int knownMacs = 0;
int channel = 1;
int timer = 60; // Set to 0 or less for infinite duration of entries

const wifi_promiscuous_filter_t filt={
    .filter_mask=WIFI_PROMIS_FILTER_MASK_MGMT|WIFI_PROMIS_FILTER_MASK_DATA
};

typedef struct { 
  uint8_t mac[6];
} __attribute__((packed)) MacAddr;

typedef struct { 
  int16_t fctl;
  int16_t duration;
  MacAddr da;
  MacAddr sa;
  MacAddr bssid;
  int16_t seqctl;
  unsigned char payload[];
} __attribute__((packed)) WifiMgmtHdr;

void sniffer(void* buf, wifi_promiscuous_pkt_type_t type) { 
  int channel1 = channel;
  wifi_promiscuous_pkt_t *p = (wifi_promiscuous_pkt_t*)buf;
  int len = p->rx_ctrl.sig_len;
  WifiMgmtHdr *wh = (WifiMgmtHdr*)p->payload;
  len -= sizeof(WifiMgmtHdr);
  if (len < 0) return;
  String packet;
  String mac;
  String info;
  int fctl = ntohs(wh->fctl);
  for(int i=0;i<=20;i++){ // i <=  len
     String hpay=String(p->payload[i],HEX);
     if(hpay.length()==1)hpay="0"+hpay;
     packet += hpay;
  }
  for(int i=10;i<=15;i++){ // extract MAC address 
     String hpay=String(p->payload[i],HEX);
     if(hpay.length()==1)hpay="0"+hpay;
     mac += hpay;
     if(i<15)mac+=":";
  }
  mac.toUpperCase();
  info="MAC = " + mac + " channel=" + channel1 + " in " + packet+"(...)";
  int added = 0;
  for(int i=0;i<=maxMacs;i++){ // check if MAC address is known
    if(mac == macList[i][0]){ // if the MAC address is known, reset the time remaining 
      macList[i][1] = String(timer);
      added = 1;
    }
  }
  if(added == 0){ // Add new entry to the array if added==0
    macList[knownMacs][0] = mac;
    macList[knownMacs][1] = String(timer);
    macList[knownMacs][2] = String(channel);
    if (debugMode == true) 
      Serial.println(info);
    else     
      Serial.printf("\r\n%d MACs detected.\r\n",knownMacs);
    knownMacs ++;
    if(knownMacs > maxMacs){
      Serial.println("Warning: MAC overflow");
      knownMacs = 0;
    }
  }
}

void updateTimer(){ // update time remaining for each known device
  for(int i=0;i<maxMacs;i++){
    if(!(macList[i][0] == "")){
      int newTime = (macList[i][1].toInt());
      newTime --;
      if(newTime <= 0){
        macList[i][1] = String(timer);
      }else{
        macList[i][1] = String(newTime);
      }
    }
  }
}

void showMyMACs(){ // show the MACs that are on both macList and macList2.
 
  int counter=0;
  for(int i=0;i<maxMacs;i++){
    if(!(macList[i][0] == "")){
      for(int j=0;j<maxMacs2;j++){
        if(macList[i][0] == macList2[j][1]){
          counter += 1;
          (String(counter) +  ". MAC=" + macList[i][0] + "  ALIAS=" + macList2[j][0] + "  Channel=" + macList[i][2] + "  Timer=" + macList[i][1] + "\r\n");
          Serial.print("\r\n"+(String(counter) +  ". MAC=" + macList[i][0] + "  ALIAS=" + macList2[j][0] + "  Channel=" + macList[i][2] + "  Timer=" + macList[i][1] + "\r\n"));
          //digitalWrite(LED, HIGH);
        }
      }
    }
  }
}

void setup() {

  Serial.begin(115200);
 /*   delay(10);

  WiFi.mode(WIFI_STA);
  WiFi.begin(ssid, password);

Serial.println("Started");
Serial.print("Connecting");
  while (WiFi.status() != WL_CONNECTED) {
    delay(500);
    Serial.print(".");
    
  }
  Serial.println("Ready to go");*/
  ////////////////////////////////////////////////////////////////////////
  Serial.printf("\n\nSDK version:%s\n\r", system_get_sdk_version());
  wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
  esp_wifi_init(&cfg);
  esp_wifi_set_storage(WIFI_STORAGE_RAM);
  esp_wifi_set_mode(WIFI_MODE_NULL);
  esp_wifi_start();
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_promiscuous_filter(&filt);
  esp_wifi_set_promiscuous_rx_cb(&sniffer);
  esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
  //pinMode(LED, OUTPUT);
}

void loop() {
    if(channel > 14) channel = 1;
    esp_wifi_set_channel(channel, WIFI_SECOND_CHAN_NONE);
    delay(1000);
    if (timer>0) updateTimer();
    if (debugMode == false) showMyMACs();
    channel++;  
   
    //////////////////////////
  /*  sendData("tag=adc_A0&value="+macList2[10][0]);
    delay(sendInterval);*/
    
  }

/*void sendData(String params) {
   HTTPClient http;
   String url="https://script.google.com/macros/s/"+GOOGLE_SCRIPT_ID+"/exec?"+params;
   Serial.print(url);
    Serial.print("Making a request");
    http.begin(url, root_ca); //Specify the URL and certificate
    int httpCode = http.GET();  
    http.end();
    Serial.println(": done "+httpCode);
}
*/
