#include <ros/ros.h>
#include <std_msgs/String.h>
#include <nlohmann/json.hpp>
#include <stdint.h>
#include <string>
#include <string.h>
#include <stdio.h>
#include <stdbool.h>
#include <openssl/aes.h>
#include "../include/crypto.h"
#include "../include/type.h"
#include "../include/convert.h"
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <cv_bridge/cv_bridge.h>
#include <image_transport/image_transport.h>
#include <opencv2/highgui/highgui.hpp>
#include <sensor_msgs/image_encodings.h>
#include <pthread.h>
#include <chrono>
#include <thread>
#include <opencv2/core.hpp>
#include "rapidjson/document.h"
#include "rapidjson/writer.h"
#include "rapidjson/stringbuffer.h"

#include <queue>
#include <mutex>

//#include "base64.h"
using json = nlohmann::json;


// #define LOG_SUB_TIME
// #define LOG_PUB_TIME

// #define _320x240_
// #define _640x480_
// #define _1280x720_
#define _1920x1080_

// #define _SUB_SHOW_IMAGE_

std::queue<cv::Mat> imageQueue;  // Queue to store captured images
std::mutex queueMutex;  // Mutex to protect the image queue

pthread_t thread1;
pthread_t thread2;
bool TIME_START = false;
uint32_t CNT_SUB = 0;
uint32_t CNT_PUB = 0;


std::string encryptMessageV2(std::string message)
{
    //ROS_INFO("encryptMessageV2");
    auto start_mem = std::chrono::high_resolution_clock::now();
    uint8_t *json_msg_enc;
    uint32_t json_msg_enc_mem_size = sizeof(uint8_t) * (int(message.length()) + 1024);
	uint8_t *json_msg_enc_str;
    uint32_t json_msg_enc_str_mem_size = sizeof(uint8_t) * (int(message.length()) + 1024) *2;

	uint32_t json_msg_enc_size = 0;
	uint32_t json_msg_enc_str_size = 0;
    //uint32_t json_msg_enc_mem_size = uint32_t(sizeof(uint8_t) * (int(message.length()) + 1024));
    std::string ret_str = "";
    auto end_mem = std::chrono::high_resolution_clock::now();

    //printf("json_msg_enc_mem_size = %d\r\n",json_msg_enc_mem_size);
    //printf("json_msg_enc_str_mem_size = %d\r\n",json_msg_enc_str_mem_size);
    //printf("message = %s, message.length() = %ld\r\n",message.c_str(),message.length());

    json_msg_enc = (uint8_t *)malloc(json_msg_enc_mem_size);
    memset(json_msg_enc,0,json_msg_enc_mem_size);

    json_msg_enc_str = (uint8_t *)malloc(json_msg_enc_str_mem_size);
    memset(json_msg_enc_str,0,json_msg_enc_str_mem_size);

    auto start_aes256Encrypt = std::chrono::high_resolution_clock::now();
    json_msg_enc_size = aes256Encrypt((uint8_t *)message.c_str(),strlen(message.c_str()),json_msg_enc,json_msg_enc_mem_size);
    auto end_aes256Encrypt = std::chrono::high_resolution_clock::now();

    //json_msg_enc_size = aes512Encrypt((uint8_t *)message.c_str(),strlen(message.c_str()),json_msg_enc,json_msg_enc_mem_size);
    //printf("json_msg_enc_size = %d\r\n",json_msg_enc_size);
    auto start_bytesToHex = std::chrono::high_resolution_clock::now();
    //json_msg_enc_str_size = bytearray_to_hexstr(json_msg_enc,json_msg_enc_size,json_msg_enc_str,json_msg_enc_str_mem_size);
    ret_str = bytesToHex(json_msg_enc,json_msg_enc_size);

    
    auto end_bytesToHex = std::chrono::high_resolution_clock::now();
    

    //ret_str = std::string((char *)json_msg_enc_str);

    //printf("ret_str len = %ld\r\n",ret_str.length());


    auto start_mem_fee = std::chrono::high_resolution_clock::now();
    free(json_msg_enc);
    free(json_msg_enc_str);
    auto end_mem_fee = std::chrono::high_resolution_clock::now();


    auto duration_aes256Encrypt = std::chrono::duration_cast<std::chrono::microseconds>(end_aes256Encrypt - start_aes256Encrypt);
    auto duration_bytesToHex = std::chrono::duration_cast<std::chrono::microseconds>(end_bytesToHex - start_bytesToHex);
    auto duration_mem = std::chrono::duration_cast<std::chrono::microseconds>(end_mem - start_mem);
    auto duration_mem_free = std::chrono::duration_cast<std::chrono::microseconds>(end_mem_fee - start_mem_fee);
    double micro_sec_aes256Encrypt = duration_aes256Encrypt.count();
    double micro_bytesToHex = duration_bytesToHex.count();
    double micro_sec_mem = duration_mem.count();
    double micro_sec_mem_free = duration_mem_free.count();
    

    //std::cout << "micro_sec_aes256Encrypt: " << micro_sec_aes256Encrypt << " us" << std::endl;
    //std::cout << "micro_bytesToHex: " << micro_bytesToHex << " us" << std::endl;
    //std::cout << "Memory allocation time: " << micro_sec_mem << " us" << std::endl;
    //std::cout << "Memory free time: " << micro_sec_mem_free << " us" << std::endl;
    //std::cout << "Memory time: " << micro_sec_mem + micro_sec_mem_free << " us" << std::endl;
    //std::cout << "Total time: " << micro_sec + micro_sec_mem + micro_sec_mem_free << " us" << std::endl;


    //char report[200] = {0};
    //sprintf(report,"echo \"%ld,%ld,%ld\" >> \"/media/psf/ROS/l2/result/time2.txt\"",duration.count(),duration_mem.count(),duration_mem_free.count());
    //sprintf(report,"echo %ld >> \"/media/psf/ROS/l2/result/time2.txt\"",duration.count());
    //system(report);

    return ret_str;

}
}
std::string decryptMessageV2(std::string encryptMessage)
{
    
	uint8_t *json_msg_enc;
	uint32_t json_msg_enc_len = 0;
    uint32_t json_msg_enc_mem_size = sizeof(uint8_t) * (int(encryptMessage.length()) + 1024);
	uint8_t *json_msg;
	uint32_t json_msg_len = 0;
    uint32_t json_msg_mem_size = sizeof(uint8_t) * (int(encryptMessage.length()) + 1024);
    std::string ret_str = "";

    //printf("encryptMessage len = %d\r\n",encryptMessage.length());
    //printf("json_msg_enc_mem_size = %d\r\n",json_msg_enc_mem_size);
    //printf("json_msg_mem_size = %d\r\n",json_msg_mem_size);

    if (encryptMessage.length() == 0) {
        return "";
    }


    json_msg_enc = (uint8_t *)malloc(json_msg_enc_mem_size);
    memset(json_msg_enc,0,json_msg_enc_mem_size);

    json_msg = (uint8_t *)malloc(json_msg_mem_size);
    memset(json_msg,0,json_msg_mem_size);


    auto start_hexToBytes = std::chrono::high_resolution_clock::now();
    json_msg_enc_len = hexToBytes((uint8_t *)encryptMessage.c_str(),encryptMessage.length(),json_msg_enc,json_msg_enc_mem_size);
    //std::cout << "\ttime hexstr_to_bytearray : " << execution_time(start_hexToBytes) << std::endl;

    auto start_aes256Decrypt = std::chrono::high_resolution_clock::now();
    json_msg_len = aes256Decrypt(json_msg_enc,json_msg_enc_len,json_msg,json_msg_mem_size);
    //std::cout << "\ttime decrypt256_data : " << execution_time(start_aes256Decrypt) << std::endl;


    ret_str = std::string((char *)json_msg);
    //printf("ret_str len = %d\r\n",ret_str.length());

    free(json_msg_enc);
    free(json_msg);

    return ret_str;

}

std::string createPlainStringMessage(bool encypt,std::string dataString)
{

    std::string encMsg = "";

    if(encypt)
    {
        //printf("dataString.length() = %ld\r\n",dataString.length());
        encMsg = encryptMessageV2(dataString);
    }
    else
    {
        encMsg = dataString;
    }
        //printf("encMsg.length() = %ld\r\n",encMsg.length());

    return encMsg; 
}
std::string createJSONMessage(int type,bool encypt,std::string dataString, int32_t dataInt32)
{
    auto start = std::chrono::high_resolution_clock::now();
          
    //ROS_INFO("createJSONMessage");  
    nlohmann::json json;
    nlohmann::json jsonData;

    jsonData["String"] = dataString;
    jsonData["Int32"] = dataInt32;

    json["Type"] = type;
    json["Time"] = (unsigned long)time(NULL);

    if(encypt)
    {
        //ROS_INFO("createJSONMessage, encypt data");  
        std::string encMsg = encryptMessageV2(jsonData.dump());
        json["Data"] = encMsg;
        //std::cout << "encypted message size = " << encMsg.length() << " byte" << std::endl;
        //printf("dataString.length() = %ld\r\n",dataString.length());
        //printf("decryptMessage = %s\r\n",decryptMessage(encMsg).c_str());
    }
    else
    {
        json["Data"] = jsonData;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    //std::cout << "createJSONMessage time: " << duration.count() << " us" << std::endl;
    //ROS_INFO("createJSONMessage, ENd");  

    auto start_dump = std::chrono::high_resolution_clock::now();
    std::string json_dump = json.dump(); 
    auto end_dump = std::chrono::high_resolution_clock::now();
    auto duration_dump = std::chrono::duration_cast<std::chrono::microseconds>(end_dump - start_dump);
    //std::cout << "duration_dump: " << duration_dump.count() << " us" << std::endl;

    return json_dump;
}


//Remove Type
std::string createJSONMessageV3(int type,bool encypt,std::string dataString)
{
    auto start = std::chrono::high_resolution_clock::now();

    std::stringstream jsonString;
    std::string jsonDataEnc;

    if(encypt)
    {
        jsonDataEnc = encryptMessageV2(dataString);
    }
    else
    {
        jsonDataEnc = dataString;
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    //std::cout << "createJSONMessage time: " << duration.count() << " us" << std::endl;

    #ifdef LOG_PUB_TIME
    double time_total = duration.count();
        char sys[200];
        sprintf(sys,"echo %.2f >> /media/psf/ROS/report/publish/exetime/time.txt",time_total);
        system(sys);
    #endif


    auto start_dump = std::chrono::high_resolution_clock::now();

    jsonString << "{\"Data\":\"" << jsonDataEnc << "\",\"Time\":" << (unsigned long)time(NULL) << ",\"Type\":" << type << "}";
    std::string json_dump = jsonString.str();


    auto end_dump = std::chrono::high_resolution_clock::now();
    auto duration_dump = std::chrono::duration_cast<std::chrono::microseconds>(end_dump - start_dump);
    //std::cout << "duration_dump: " << duration_dump.count() << " us" << std::endl;

    return json_dump;
}
//{\"Data\":\"c1055e261ce28ee03e231488ac8a26abb4d4fe0099054917c9636684aee95811\",\"Time\":1684476004,\"Type\":1}
//{"Int32":0,"String":"TEST"}
std::string createJSONMessageV2(int type,bool encypt,std::string dataString, int32_t dataInt32)
{
    auto start = std::chrono::high_resolution_clock::now();
          
    //ROS_INFO("createJSONMessage");  
    //nlohmann::json json;
    //nlohmann::json jsonData;

    //jsonData["String"] = dataString;
    //jsonData["Int32"] = dataInt32;

    //json["Type"] = type;
    //json["Time"] = (unsigned long)time(NULL);

    std::stringstream jsonDataString;
    std::stringstream jsonString;
    std::string jsonDataEnc;

    jsonDataString << "{\"Int32\":" << dataInt32  << ",\"String\":\"" << dataString << "\"}";
    if(encypt)
    {

        //ROS_INFO("createJSONMessage, encypt data");  
        //std::string jDataDump = jsonData.dump();
        //std::cout << "jDataDump = " << jDataDump << std::endl;
        //std::string encMsg = encryptMessageV2(jDataDump);
        //json["Data"] = encMsg;
        
        jsonDataEnc = encryptMessageV2(jsonDataString.str());
        //std::cout << "encypted message size = " << encMsg.length() << " byte" << std::endl;
        //printf("dataString.length() = %ld\r\n",dataString.length());
        //printf("decryptMessage = %s\r\n",decryptMessage(encMsg).c_str());
    }
    else
    {
        //json["Data"] = jsonData;
        jsonDataEnc = jsonDataString.str();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    //std::cout << "createJSONMessage time: " << duration.count() << " us" << std::endl;
    //ROS_INFO("createJSONMessage, ENd");  

    auto start_dump = std::chrono::high_resolution_clock::now();
    //std::string json_dump = json.dump(); 

    //std::stringstream jsonString;
    jsonString << "{\"Data\":\"" << jsonDataEnc << "\",\"Time\":" << (unsigned long)time(NULL) << ",\"Type\":" << type << "}";
    std::string json_dump = jsonString.str();


    auto end_dump = std::chrono::high_resolution_clock::now();
    auto duration_dump = std::chrono::duration_cast<std::chrono::microseconds>(end_dump - start_dump);
    //std::cout << "duration_dump: " << duration_dump.count() << " us" << std::endl;

    return json_dump;
}
std::string createPubMessageFile(std::string filename) 
{
    std::ifstream file_stream;
    std::string line;
    std::string text = "";

    file_stream.open(filename); // Open the file

    if (!file_stream.is_open()) {
        std::cout << "Unable to open the file " << filename << std::endl;
        return "";
    }

    while (std::getline(file_stream, line)) { // Read the file line by line
         text = text + line;
    }

    file_stream.close(); // Close the file

    //printf("Text in file : %s\r\n",text.c_str());
    std::cout << "file size = " << text.length() << " byte" << std::endl;
    return createJSONMessageV2(TYPE_eString,true,text,0);
    //return createPlainStringMessage(true,text);
}
std::string createPubMessageString(std::string data) 
{
    //ROS_INFO("createPubMessageString");
    return createJSONMessageV3(TYPE_eString,true,data);
}
std::string createPubImageString(std::string data) 
{
    //ROS_INFO("createPubMessageString");
    return createJSONMessageV3(TYPE_Image320x240,true,data);
}
std::string createPubMessageInt32(int32_t data) 
{
    return createJSONMessageV2(TYPE_eInt32,true,"",data);
}


std::vector<unsigned char> hexStringToVector2(const std::string& hexString) {
    std::vector<unsigned char> result;

    // Iterate over the hex string in pairs
    for (size_t i = 0; i < hexString.length(); i += 2) {
        // Extract two characters and convert them to a byte value
        std::string byteString = hexString.substr(i, 2);
        unsigned char byte = static_cast<unsigned char>(std::stoi(byteString, nullptr, 16));

        // Add the byte value to the result vector
        result.push_back(byte);
    }

    return result;
}
std::vector<unsigned char> hexStringToVector3(std::string hexString) {
    std::vector<unsigned char> result;
    int cnt = 0;
    uint8_t strh1 = 0;
    uint8_t strh2 = 0;
    for (char c : hexString) {

        if (cnt == 0) {
            strh1 = (uint8_t)c;
            cnt++;
        } else{
            strh2 = (uint8_t)c;
            cnt = 0;
            uint8_t d = hexCharsToByte(strh1,strh2);
            result.push_back(d);
        }
    }

    return result;
}


std::string extract_data_from_json_rapid(const std_msgs::String::ConstPtr& msg) {

    std::string data = "";

    rapidjson::Document document;
    document.Parse(msg->data.c_str());
    const rapidjson::Value& jrapidData = document["Data"];
    if (jrapidData.IsString()) {
        std::string data = jrapidData.GetString();
        std::cout << "Extracted string len : " << data.length() << std::endl;
    }

    return data;
}


std::string extract_data_from_json_substr(const std_msgs::String::ConstPtr& msg) {

    std::string jsonString = msg->data;
    std::string startSearch = R"({"Data":")";
    std::string endSearch = R"(","Time":)";
    size_t startIndex = jsonString.find(startSearch) + startSearch.length();
    size_t endIndex = jsonString.find(endSearch);


    // std::cout << "startIndex: " << startIndex << std::endl;
    // std::cout << "endIndex: " << endIndex << std::endl;

    return jsonString.substr(startIndex, endIndex - startIndex);

    // std::cout << "Extracted string: " << extractedString << std::endl;


}

std::string extract_data_from_json(const std_msgs::String::ConstPtr& msg) {

    std::string data = "";
    uint32_t slen =  msg->data.length();
    uint8_t st = 0;
                    //std::cout << "slen = " << slen << std::endl;
    for(uint32_t i = 0; i < slen; i++) {
        switch(st) {
            case 0:
                if (msg->data.c_str()[i] == '\"') {
                    st = 1;
                    //std::cout << "st = 1" << std::endl;
                }
                break;
            case 1:
                if (msg->data.c_str()[i] == 'D' || msg->data.c_str()[i] == 'd') {
                    st = 2;
                } else {
                    st = 0;
                }
                break;
            case 2:
                if (msg->data.c_str()[i] == 'a') {
                    st = 3;
                } else {
                    st = 0;
                }
                break;
            case 3:
                if (msg->data.c_str()[i] == 't') {
                    st = 4;
                } else {
                    st = 0;
                }
                break;
            case 4:
                if (msg->data.c_str()[i] == 'a') {
                    st = 5;
                } else {
                    st = 0;
                }
                break;
            case 5:
                if (msg->data.c_str()[i] == '\"') {
                    st = 6;
                } else {
                    st = 0;
                };
                break;
            case 6:
                if (msg->data.c_str()[i] == ' ') { 

                } else if (msg->data.c_str()[i] == ':') { 
                    st = 7;
                } else {
                    st = 0;
                }
                break;
            case 7:
                if (msg->data.c_str()[i] == ' ') { 

                } else if (msg->data.c_str()[i] == '\"') { 
                    st = 8;
                } else {
                    st = 0;
                }
                break;
            case 8:
                if (msg->data.c_str()[i] == '\"') { 
                    st = 9;
                    return data;
                } else {
                    data.push_back(msg->data.c_str()[i]);
                }
                break;
        }
    }

    return data;
}


std::string extract_string_from_json(std::string msg) {

    std::string data = "";
    uint32_t slen =  msg.length();
    uint8_t st = 0;
    for(uint32_t i = 0; i < slen; i++) {
        switch(st) {
            case 0:
                if (msg.c_str()[i] == '\"') {
                    st = 1;
                    //std::cout << "st = 1" << std::endl;
                }
                break;
            case 1:
                if (msg.c_str()[i] == 'S' || msg.c_str()[i] == 's') {
                    st = 2;
                } else {
                    st = 0;
                }
                break;
            case 2:
                if (msg.c_str()[i] == 't') {
                    st = 3;
                } else {
                    st = 0;
                }
                break;
            case 3:
                if (msg.c_str()[i] == 'r') {
                    st = 4;
                } else {
                    st = 0;
                }
                break;
            case 4:
                if (msg.c_str()[i] == 'i') {
                    st = 5;
                } else {
                    st = 0;
                }
                break;
            case 5:
                if (msg.c_str()[i] == 'n') {
                    st = 6;
                } else {
                    st = 0;
                }
                break;
            case 6:
                if (msg.c_str()[i] == 'g') {
                    st = 7;
                } else {
                    st = 0;
                }
                break;
            case 7:
                if (msg.c_str()[i] == '\"') {
                    st = 8;
                } else {
                    st = 0;
                };
                break;
            case 8:
                if (msg.c_str()[i] == ' ') { 

                } else if (msg.c_str()[i] == ':') { 
                    st = 9;
                } else {
                    st = 0;
                }
                break;
            case 9:
                if (msg.c_str()[i] == ' ') { 

                } else if (msg.c_str()[i] == '\"') { 
                    st = 10;
                } else {
                    st = 0;
                }
                break;
            case 10:
                if (msg.c_str()[i] == '\"') { 
                    return data;
                } else {
                    data.push_back(msg.c_str()[i]);
                }
                break;
        }
    }

    return data;
}

int extract_type_from_json(const std_msgs::String::ConstPtr& msg) {

    std::string data = "";
    uint32_t slen =  msg->data.length();
    uint8_t st = 0;
                    //std::cout << "slen = " << slen << std::endl;
    for(uint32_t i = 0; i < slen; i++) {
        switch(st) {
            case 0:
                if (msg->data.c_str()[i] == '\"') {
                    st = 1;
                    //std::cout << "st = 1" << std::endl;
                }
                break;
            case 1:
                if (msg->data.c_str()[i] == 'T' || msg->data.c_str()[i] == 't') {
                    st = 2;
                } else {
                    st = 0;
                }
                break;
            case 2:
                if (msg->data.c_str()[i] == 'y') {
                    st = 3;
                } else {
                    st = 0;
                }
                break;
            case 3:
                if (msg->data.c_str()[i] == 'p') {
                    st = 4;
                } else {
                    st = 0;
                }
                break;
            case 4:
                if (msg->data.c_str()[i] == 'e') {
                    st = 5;
                } else {
                    st = 0;
                }
                break;
            case 5:
                if (msg->data.c_str()[i] == '\"') {
                    st = 6;
                } else {
                    st = 0;
                };
                break;
            case 6:
                if (msg->data.c_str()[i] == ' ') { 

                } else if (msg->data.c_str()[i] == ':') { 
                    st = 7;
                } else {
                    st = 0;
                }
                break;
            case 7:
                if (msg->data.c_str()[i] == ' ') { 

                } else if (msg->data.c_str()[i] >= '0' && msg->data.c_str()[i] <= '9') { 
                    return msg->data.c_str()[i] - '0';
                } 
                st = 0;
                
                break;
        }
    }

    return 0;
}
//\"Data\":\"c1055e261ce28ee03e231488ac8a26abb4d4fe0099054917c9636684aee95811\",
//{\"Data\":\"c1055e261ce28ee03e231488ac8a26abb4d4fe0099054917c9636684aee95811\",\"Time\":1684476004,\"Type\":1}
void subMessageCallback(const std_msgs::String::ConstPtr& msg)
{
    //printf("subMessageCallback : %s\r\n",msg->data.c_str());
    auto start_cb = std::chrono::high_resolution_clock::now();
    if (msg->data.length() > 0) {

        if (msg->data.c_str()[0] == '{' && msg->data.c_str()[msg->data.length()-1] == '}') {

                
            //auto start_json_parse = std::chrono::high_resolution_clock::now();
            //json jst = json::parse(msg->data);
            //std::cout << "time json_parse : " << execution_time(start_json_parse) << std::endl;
            //execution_time
            /*
            auto start_json_parse = std::chrono::high_resolution_clock::now();
            json jst = json::parse(msg->data);
            std::cout << "time json_parse : " << execution_time(start_json_parse) << std::endl;


            auto start_json_data_get = std::chrono::high_resolution_clock::now();
            std::string encryptData = jst["Data"].get<std::string>();
            std::cout << "time json_data_get : " << execution_time(start_json_data_get) << std::endl;


            auto start_decryptMessageV2 = std::chrono::high_resolution_clock::now();
            std::string plainData = decryptMessageV2(encryptData);
            std::cout << "time decryptMessageV2 : " << execution_time(start_decryptMessageV2) << std::endl;
            //printf("plainData : %s\r\n",plainData.c_str());
            */

            auto start_extract_data_from_json = std::chrono::high_resolution_clock::now();
            // std::string data_json_get = extract_data_from_json(msg);
            // std::cout << "time extract_data_from_json : " << execution_time(start_extract_data_from_json) << std::endl;

            std::string data_json_get = extract_data_from_json_substr(msg);
            //std::cout << "time extract_data_from_json_substr : " << execution_time(start_extract_data_from_json) << std::endl;

            
            //std::cout << "data_json_get : " << data_json_get << std::endl;
            // std::cout << "time extract_data_from_json : " << execution_time(start_extract_data_from_json) << std::endl;

            auto start_decryptMessageV2 = std::chrono::high_resolution_clock::now();
            std::string str_data = decryptMessageV2(data_json_get);
            double time_execu =  execution_time(start_decryptMessageV2);
            //std::cout << "time decryptMessageV2 : " << time_execu << std::endl;

            #ifdef LOG_SUB_TIME
                char sys[200];
                sprintf(sys,"echo %.2f >> /media/psf/ROS/report/subscribe/exetime/time.txt",time_execu);
                system(sys);
            #endif


            //auto start_json_parse2 = std::chrono::high_resolution_clock::now();
            //json jdata = json::parse(plainData);
            //std::cout << "time json_parse2 : " << execution_time(start_json_parse2) << std::endl;
            int type;

            if (data_json_get.length() > 10000) {
                type = TYPE_Image320x240;
            } else {
                auto start_extract_type_from_json = std::chrono::high_resolution_clock::now();
                type = extract_type_from_json(msg);
                //std::cout << "time extract_type_from_json : " << execution_time(start_extract_type_from_json) << std::endl;
            }

            // std::string str_data;
            // if (type == TYPE_eInt32) {
            //     str_data = extract_string_from_json(plainData);
            // } else {
            //     auto start_extract_string_from_json = std::chrono::high_resolution_clock::now();
            //     str_data = extract_string_from_json(plainData);
            //     std::cout << "time extract_string_from_json : " << execution_time(start_extract_string_from_json) << std::endl;
            // }

            
            //V3 remove type Int32, String
            // std::string str_data;
            // if (type == TYPE_eInt32) {
            //     str_data = plainData;
            // } else {
            //     // auto start_extract_string_from_json = std::chrono::high_resolution_clock::now();
            //     str_data = plainData;
            //     // std::cout << "time extract_string_from_json : " << execution_time(start_extract_string_from_json) << std::endl;
            // }


            if(type == TYPE_eInt32)
            {
                printf("data Int32 : %s\r\n",str_data.c_str());
            }
            else if(type == TYPE_eString)
            {
                printf("data String : %s, len : %ld\r\n",str_data.c_str(),str_data.length());
            }
            else if(type == TYPE_File)
            {
                printf("data String : %s, len : %ld\r\n",str_data.c_str(),str_data.length());
            }
            else if(type == TYPE_Image320x240)
            {
                printf("data Image : len : %ld\r\n",str_data.length());

                auto start_hexStringToVector3 = std::chrono::high_resolution_clock::now();
                std::vector<unsigned char> buffer = hexStringToVector3(str_data);
                std::cout << "time hexStringToVector3 : " << execution_time(start_hexStringToVector3) << std::endl;
                //printf("Vector size = %d\r\n",buffer.size());
                //cv::Mat image(240,320, CV_8UC3, buffer.data());

                #ifdef _SUB_SHOW_IMAGE_
                    auto start_imdecode = std::chrono::high_resolution_clock::now();
                    cv::Mat image = cv::imdecode(buffer, cv::IMREAD_COLOR);
                    std::cout << "time imdecode : " << execution_time(start_imdecode) << std::endl;
                #endif


                #ifdef _SUB_SHOW_IMAGE_
                if (!image.empty())
                #else
                if(true)
                #endif
                {

                    if (TIME_START == false) {
                        TIME_START = true;
                    }
                    CNT_SUB++;
                    //auto start_namedWindow = std::chrono::high_resolution_clock::now();

                    #ifdef _SUB_SHOW_IMAGE_
                        cv::namedWindow("Image Window", cv::WINDOW_NORMAL);  // Create a window
                        cv::imshow("Image Window", image);  // Show the image in the window
                        cv::waitKey(1);  // Wait for a key press
                    #endif

                }

            }
            //std::cout << "time start_cb : " << execution_time(start_cb) << std::endl;
            printf("---\r\n");
        } else {
                std::string plainData = decryptMessageV2(msg->data);
                printf("data XXXX : %s, len : %ld\r\n",plainData.c_str(),plainData.length());
                //printf("data XXXX : xx, len : %ld\r\n",plainData.length());
            printf("XXX ---\r\n");
        }
     }

}


void subMessageCallback2(const std_msgs::String::ConstPtr& msg)
{
    //printf("subMessageCallback : %s\r\n",msg->data.c_str());
    if (msg->data.length() > 0) {

        if (msg->data.c_str()[0] == '{' && msg->data.c_str()[msg->data.length()-1] == '}') {

                
            //execution_time
            auto start_json_parse = std::chrono::high_resolution_clock::now();
            json jst = json::parse(msg->data);
            std::cout << "time json_parse : " << execution_time(start_json_parse) << std::endl;


            auto start_json_data_get = std::chrono::high_resolution_clock::now();
            std::string encryptData = jst["Data"].get<std::string>();
            std::cout << "time json_data_get : " << execution_time(start_json_data_get) << std::endl;


            auto start_decryptMessageV2 = std::chrono::high_resolution_clock::now();
            std::string plainData = decryptMessageV2(encryptData);
            std::cout << "time decryptMessageV2 : " << execution_time(start_decryptMessageV2) << std::endl;
            //printf("plainData : %s\r\n",plainData.c_str());

            json jdata = json::parse(plainData);

            if(jst["Type"] == TYPE_eInt32)
            {
                printf("data Int32 : %d\r\n",jdata["Int32"].get<int32_t>());
            }
            else if(jst["Type"] == TYPE_eString)
            {
                printf("data String : %s, len : %ld\r\n",jdata["String"].get<std::string>().c_str(),jdata["String"].get<std::string>().length());
            }
            else if(jst["Type"] == TYPE_eString)
            {
                printf("data String : %s, len : %ld\r\n",jdata["String"].get<std::string>().c_str(),jdata["String"].get<std::string>().length());
            }
            else if(jst["Type"] == TYPE_File)
            {
                printf("data String : %s, len : %ld\r\n",jdata["String"].get<std::string>().c_str(),jdata["String"].get<std::string>().length());
            }
            else if(jst["Type"] == TYPE_Image320x240)
            {
                printf("data Image : len : %ld\r\n",jdata["String"].get<std::string>().length());

                auto start_hexStringToVector3 = std::chrono::high_resolution_clock::now();
                std::vector<unsigned char> buffer = hexStringToVector3(jdata["String"].get<std::string>());
                std::cout << "time hexStringToVector3 : " << execution_time(start_hexStringToVector3) << std::endl;
                //printf("Vector size = %d\r\n",buffer.size());
                //cv::Mat image(240,320, CV_8UC3, buffer.data());
                auto start_imdecode = std::chrono::high_resolution_clock::now();
                cv::Mat image = cv::imdecode(buffer, cv::IMREAD_COLOR);
                std::cout << "time imdecode : " << execution_time(start_imdecode) << std::endl;

                if (!image.empty())
                {

                    if (TIME_START == false) {
                        TIME_START = true;
                    }
                    CNT_SUB++;
                    //auto start_namedWindow = std::chrono::high_resolution_clock::now();
                    cv::namedWindow("Image Window", cv::WINDOW_NORMAL);  // Create a window
                    //std::cout << "time namedWindow : " << execution_time(start_namedWindow) << std::endl;


                    //auto start_imshow = std::chrono::high_resolution_clock::now();
                    cv::imshow("Image Window", image);  // Show the image in the window
                    //std::cout << "time imshow : " << execution_time(start_imshow) << std::endl;

                    //auto start_waitKey = std::chrono::high_resolution_clock::now();
                    cv::waitKey(1);  // Wait for a key press
                    //std::cout << "time waitKey : " << execution_time(start_waitKey) << std::endl;

                }

            }
            printf("---\r\n");
        } else {
                std::string plainData = decryptMessageV2(msg->data);
                printf("data XXXX : %s, len : %ld\r\n",plainData.c_str(),plainData.length());
                //printf("data XXXX : xx, len : %ld\r\n",plainData.length());
            printf("XXX ---\r\n");
        }
     }
}

bool pubOneMessageX(char *topic, char *type, char *data,uint32_t time)
{
   ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic),1000);
    //ros::Publisher publisher = nh.advertise<std_msgs::String>("encypt_message_publisher",1000);
    std_msgs::String msg;
    ros::Rate loop_rate(1000); //In Herz
    ros::Rate loop_rate2(0.5);
    ros::Rate poll_rate(2);
    uint32_t loop_cnt = 0;
    bool first = true;
    while(ros::ok())
    {
        if (first) {
            first = false;
            while(publisher.getNumSubscribers() == 0)
            {
                //ROS_ERROR("Waiting for subscibers");
                poll_rate.sleep();
            }
        //loop_rate.sleep(); 
            loop_rate2.sleep(); //Sleep 2sec
        }
        //printf("publisher.getNumSubscribers() = %d\r\n",publisher.getNumSubscribers());
        //ROS_ERROR("Got subscriber");
        //printf("ros::ok, topic : %s, type : %s, data : %s\r\n",topic,type,data);
        
        if(strncmp(type,"Int32",5) == 0 || strncmp(type,"int32",5) == 0)
        {
            msg.data = createPubMessageInt32(atoi(data));
        }
        else if(strncmp(type,"String",6) == 0 || strncmp(type,"string",6) == 0)
        {
            msg.data = createPubMessageString(std::string(data));
        }
        else if(strncmp(type,"File",4) == 0 || strncmp(type,"file",4) == 0)
        {
            auto start = std::chrono::high_resolution_clock::now();
            msg.data = createPubMessageFile(std::string(data));
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "createPubMessageFile time: " << duration.count() << " us" << std::endl;
            char report[200] = {0};
            sprintf(report,"echo %ld >> \"/media/psf/ROS/l2/result/createPub.txt\"",duration.count());
            system(report);
        }
        else
        {
            return false;
        }

        //printf("message : %s\r\n",msg.data.c_str());
        //printf("message : %s\r\n",msg.data.c_str());
        if (msg.data != "") {
            publisher.publish(msg);
        } else {

        }
        ros::spinOnce();
        loop_rate.sleep(); 

        loop_cnt++;
        if (time > 0) {
            if (loop_cnt > (time-1)) {
                return true;
            }
        }


    }

    return false;
}
bool pubOneMessage(char *topic, char *type, char *data)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic),1000);
    //ros::Publisher publisher = nh.advertise<std_msgs::String>("encypt_message_publisher",1000);
    std_msgs::String msg;
    ros::Rate loop_rate(1); //In Herz
    //ros::Rate loop_rate2(2);
    ros::Rate poll_rate(2);
    while(ros::ok())
    {
        //ROS_INFO("ros::ok()");
        while(publisher.getNumSubscribers() == 0)
        {
            //ROS_ERROR("Waiting for subscibers");
            poll_rate.sleep();
        }
        loop_rate.sleep(); 
        //loop_rate2.sleep();
        //printf("publisher.getNumSubscribers() = %d\r\n",publisher.getNumSubscribers());
        //ROS_ERROR("Got subscriber");
        //printf("ros::ok, topic : %s, type : %s, data : %s\r\n",topic,type,data);
        
        if(strncmp(type,"Int32",5) == 0 || strncmp(type,"int32",5) == 0)
        {
            msg.data = createPubMessageInt32(atoi(data));
        }
        else if(strncmp(type,"String",6) == 0 || strncmp(type,"string",6) == 0)
        {
            //ROS_INFO("Type : String");
            msg.data = createPubMessageString(std::string(data));
        }
        else if(strncmp(type,"File",4) == 0 || strncmp(type,"file",4) == 0)
        {
            auto start = std::chrono::high_resolution_clock::now();
            msg.data = createPubMessageFile(std::string(data));
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "createPubMessageFile time: " << duration.count() << " us" << std::endl;

        }
        else
        {
            return false;
        }

        //printf("message : %s\r\n",msg.data.c_str());
        //printf("message : %s\r\n",msg.data.c_str());
        if (msg.data != "") {
            publisher.publish(msg);
        } else {

        }
        ros::spinOnce();
        loop_rate.sleep(); 


        return true;
    }

    return false;

}

std::string vectorToHexString2(const std::vector<unsigned char>& vector) {
    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    
    for (const auto& element : vector) {
        oss << std::setw(2) << static_cast<int>(element);
    }
    
    return oss.str();
}
std::string vectorToHexString(const std::vector<uint8_t>& vector) {
    constexpr char hexDigits[] = "0123456789ABCDEF";
    const size_t size = vector.size();
    std::string hexString(size * 2, ' ');

    for (size_t i = 0; i < size; ++i) {
        hexString[2 * i] = hexDigits[(vector[i] >> 4) & 0x0F];
        hexString[2 * i + 1] = hexDigits[vector[i] & 0x0F];
    }

    return hexString;
}
bool pubStreamEncryptImage(char *topic)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic),1000);
    //ros::Publisher publisher = nh.advertise<std_msgs::String>("encypt_message_publisher",1000);
    std_msgs::String msg;
    ros::Rate loop_rate(100000); //In Herz
    //ros::Rate loop_rate2(2);
    ros::Rate poll_rate(1);


    // 0 reads from your default camera
    const int CAMERA_INDEX = 0;
    cv::VideoCapture capture(CAMERA_INDEX); 

    if (!capture.isOpened()) {
      ROS_ERROR_STREAM("Failed to open camera with index " << CAMERA_INDEX << "!");
      ros::shutdown();
    }


    #ifdef _320x240_
        std::cout << "_320x240_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH,320);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT,240);
    #elif defined(_640x480_)
        std::cout << "_640x480_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH,640);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT,480);
    #elif defined(_1280x720_)
        std::cout << "_1280x720_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH,1280);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT,720);
    #elif defined(_1920x1080_)
        std::cout << "_1920x1080_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH,1920);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT,1080);
    #else
        std::cout << "Default _320x240_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH,320);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT,240);
    #endif

    cv::Mat frame;//Mat is the image class defined in OpenCV


    printf("publish started\r\n");
    
    bool first = true;
    while (nh.ok())
    {
        if (first) {
            first = false;
            while(publisher.getNumSubscribers() == 0)
            {
                ROS_ERROR("Waiting for subscibers");
                poll_rate.sleep();
            }
        //loop_rate.sleep(); 
            poll_rate.sleep(); //Sleep 2sec
            TIME_START = true;
        }
        //loop_rate2.sleep();
        //printf("publisher.getNumSubscribers() = %d\r\n",publisher.getNumSubscribers());
        //ROS_ERROR("Got subscriber");
        //printf("ros::ok, topic : %s, type : %s, data : %s\r\n",topic,type,data);
        
        auto start_total = std::chrono::high_resolution_clock::now();
        capture >> frame; 
        std::cout << "time capture >> frame : " << execution_time(start_total) << std::endl;

        if (frame.empty()) {
            ROS_ERROR_STREAM("Failed to capture image!");
            ros::shutdown();
        }

        /*
        int colorType = frame.type();

        if (colorType == CV_8UC1) {
            std::cout << "Grayscale image" << std::endl;
        } else if (colorType == CV_8UC3) {
            std::cout << "RGB color image CV_8UC3" << std::endl;
        } else if (colorType == CV_8UC4) {
            std::cout << "RGBA color image CV_8UC4" << std::endl;
        } else {
            std::cout << "Unknown color type" << std::endl;
        }
        std::cout << "Image dimensions: " << frame.cols << "x" << frame.rows << std::endl;
        */

        auto start_encode = std::chrono::high_resolution_clock::now();
        std::vector<uchar> buffer;
        cv::imencode(".png", frame, buffer);
        auto end_encode = std::chrono::high_resolution_clock::now();
        auto duration_encode = std::chrono::duration_cast<std::chrono::microseconds>(end_encode - start_encode);
        double micro_sec_encode = duration_encode.count();
        //printf("micro_sec_encode = %f us\r\n",micro_sec_encode);
  

        auto start_vector2Str = std::chrono::high_resolution_clock::now();
        std::string ImageString = "";
        
        /*
        char chData[10] = {0};
        for (unsigned char byte : buffer) {
            memset(chData,0,sizeof(chData));
            sprintf(chData,"%02X",static_cast<uint8_t>(byte));
            ImageString = ImageString + chData;
        }
        */
        ImageString = vectorToHexString(buffer);
        
        auto end_vector2Str = std::chrono::high_resolution_clock::now();
        auto duration_vector2Str = std::chrono::duration_cast<std::chrono::microseconds>(end_vector2Str - start_vector2Str);
        double micro_sec_vector2Str = duration_vector2Str.count();
        printf("micro_sec_vector2Str = %f us\r\n",micro_sec_vector2Str);


        auto start_pubStr = std::chrono::high_resolution_clock::now();
        std::string encimg = createPubImageString(ImageString);
        auto end_pubStr = std::chrono::high_resolution_clock::now();
        auto duration_pubStr = std::chrono::duration_cast<std::chrono::microseconds>(end_pubStr - start_pubStr);
        double micro_sec_pubStr = duration_pubStr.count();
        printf("micro_sec_pubStr = %f us\r\n",micro_sec_pubStr);
        //std::cout << encimg << std::endl;
 
        CNT_PUB++;

        msg.data = encimg;


        std::cout << "time total : " << execution_time(start_total) << std::endl;

        if (msg.data != "") {
            publisher.publish(msg);
        } else {

        }


        ros::spinOnce();
        loop_rate.sleep(); 


        //return true;
    }
    capture.release();

    return false;

}


void * captureThread(void *arguments) {
    cv::VideoCapture cap(0);  // Open the default camera (0) or specify a camera index


    if (!cap.isOpened()) {
        std::cout << "Failed to open camera!" << std::endl;
        
    } else {
        cap.set(cv::CAP_PROP_FRAME_WIDTH,320);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT,240);

        while (true) {
            cv::Mat frame;
            cap >> frame;  // Capture frame from the camera

            //std::lock_guard<std::mutex> lock(queueMutex);
            imageQueue.push(frame);  // Put the captured frame into the queue
            printf("En Qsize : %ld\r\n",imageQueue.size());

            //usleep(30000);
            usleep(100000);

        }
    }
    return static_cast<void*>(0);
}

bool pubStreamEncryptImagePipe(char *topic)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic),1000);
    std_msgs::String msg;
    ros::Rate loop_rate(100000); //In Herz
    //ros::Rate loop_rate2(2);
    ros::Rate poll_rate(1);


    // 0 reads from your default camera
    //const int CAMERA_INDEX = 0;
    //cv::VideoCapture capture(CAMERA_INDEX); 

    //if (!capture.isOpened()) {
    //  ROS_ERROR_STREAM("Failed to open camera with index " << CAMERA_INDEX << "!");
    //  ros::shutdown();
    //}

    //capture.set(cv::CAP_PROP_FRAME_WIDTH,320);
    //capture.set(cv::CAP_PROP_FRAME_HEIGHT,240);


    pthread_create(&thread2, NULL, captureThread, NULL);
    cv::Mat frame;//Mat is the image class defined in OpenCV

    //poll_rate.sleep();
    //poll_rate.sleep();
    //poll_rate.sleep();
    //poll_rate.sleep();
    //printf("publish started\r\n");

    bool first = true;
    //std::thread captureThread(captureThread);

    while (nh.ok())
    {
        if (first) {
            first = false;
            while(publisher.getNumSubscribers() == 0)
            {
                ROS_ERROR("Waiting for subscibers");
                poll_rate.sleep();
            }
            poll_rate.sleep(); //Sleep 2sec
            TIME_START = true;
        }


        //capture >> frame; 

        //std::lock_guard<std::mutex> lock(queueMutex);
        if (!imageQueue.empty()) {
            frame = imageQueue.front();  // Get the first image from the queue
            imageQueue.pop();  // Remove the processed image from the queue
            printf("De Qsize : %ld\r\n",imageQueue.size());

            if (frame.empty()) {
                ROS_ERROR_STREAM("Failed to capture image!");
                ros::shutdown();
            }


            std::vector<uchar> buffer;
            cv::imencode(".png", frame, buffer);

            std::string ImageString = "";
            char chData[10] = {0};
            for (unsigned char byte : buffer) {
                memset(chData,0,sizeof(chData));
                sprintf(chData,"%02X",static_cast<uint8_t>(byte));
                ImageString = ImageString + chData;
            }

            printf("hexString.length = %ld\r\n",ImageString.length());
            std::string encimg = createPubImageString(ImageString);
            //std::cout << encimg << std::endl;
    
            CNT_PUB++;

            msg.data = encimg;

            if (msg.data != "") {
                publisher.publish(msg);
            } else {

            }
            ros::spinOnce();
            loop_rate.sleep(); 
        }


    }
    //captureThread.join();
    //capture.release();

    return false;

}
/*
app [act] [topic] [type] [data]
    - act echo, pub
    - type Int32, String
*/
void * ThTimer(void *arguments)
{
    double cnt = 0;
    uint32_t pv_sub = 0;
    uint32_t pv_pub = 0;
    uint32_t sub_per_sec = 0;
    uint32_t pub_per_sec = 0;

    double avg_sub_per_sec = 0;
    double avg_pub_per_sec = 0;

    while(1) 
    {
        if (TIME_START) {
            sub_per_sec = CNT_SUB - pv_sub;
            pub_per_sec = CNT_PUB - pv_pub;
            
            pv_sub = CNT_SUB;
            pv_pub = CNT_PUB;

            cnt++;

            avg_sub_per_sec = double(CNT_SUB) / cnt;
            avg_pub_per_sec = double(CNT_PUB) / cnt;


            if (pub_per_sec > 0) {
                printf("\r\n ----> Publish rate %d fps, AVG %.2f fps <---- \r\n",pub_per_sec,avg_pub_per_sec);
            }
            if (sub_per_sec > 0) {
                printf("\r\n ----> Subscript rate %d fps, AVG %.2f fps <---- \r\n",sub_per_sec,avg_sub_per_sec);
            }
        }
        //std::this_thread::sleep_for(std::chrono::milliseconds(100));
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
  
}
/*
std::string matToBase64(const cv::Mat& mat) {
    std::vector<uchar> buffer;
    cv::imencode(".jpg", mat, buffer);
    std::string base64 = base64_encode(buffer.data(), buffer.size());
    return base64;
}
*/
void imageCallback(const sensor_msgs::ImageConstPtr& msg)
{
    try
    {
        CNT_SUB++;
        cv::imshow("view", cv_bridge::toCvShare(msg, "bgr8")->image);
        cv::waitKey(1);
    }
    catch (cv_bridge::Exception& e)
    {
        ROS_ERROR("Could not convert from '%s' to 'bgr8'.", msg->encoding.c_str());
    }
}
//https://github.com/ros-perception/vision_opencv/blob/rolling/cv_bridge/src/cv_bridge.cpp

/*
*/

//Encrypt Image
//This main for stream image via image_transport
//l2topic pub
//l2topic sub
int main(int argc, char **argv)
{
    char name[50] = {0};
    sprintf(name,"L2Topic_%lu",(unsigned long)time(NULL));
    ros::init(argc,argv,name);
    //ROS_INFO("TOPIC L2, crypto in ROS Message");

    pthread_create(&thread1, NULL, ThTimer, NULL);

    // printf("argc = %d\r\n",argc);
    // for(int i = 0; i < argc; i++) {
    //     printf("argv[%d] = %s\r\n",i,argv[i]);
    // }

    //std::string s = createJSONMessage(1,true,std::string("MDATA"),555);
    //printf("s = %s\r\n",s.c_str());

    if(argc < 3) 
    {
        ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
        return 0;
    }

    if(strncmp(argv[1],"pub100",6) == 0) 
    {
        if(argc < 5)
        {
            ROS_INFO("Not enough parameter");
            ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
            return 0;
        }

        if(pubOneMessageX(argv[2],argv[3],argv[4],100))
        {
            printf("Publish message success\r\n");
        }
        else
        {
            printf("Publish message failed\r\n");
        }

    } 
    else if(strncmp(argv[1],"pubimg2",7) == 0) 
    {
        pubStreamEncryptImagePipe(argv[2]);
    }
    else if(strncmp(argv[1],"pubimg",6) == 0) 
    {
        pubStreamEncryptImage(argv[2]);
    }
    else if(strncmp(argv[1],"echo",4) == 0) 
    {
        //printf("subscribe on topic %s\r\n",argv[2]);
        ros::NodeHandle nh;
        ros::Subscriber sub = nh.subscribe(std::string(argv[2]),100000,subMessageCallback);
        ros::spin();
    }
    else if(strncmp(argv[1],"pub",3) == 0) 
    {
            //ROS_INFO("pub");
        if(argc < 5)
        {
            ROS_INFO("Not enough parameter");
            ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
            return 0;
        }

        if(pubOneMessage(argv[2],argv[3],argv[4]))
        {
            //ROS_INFO("pubOneMessage");
            printf("Publish message success\r\n");
        }
        else
        {
            printf("Publish message failed\r\n");
        }

    } 


    return 0;
}
