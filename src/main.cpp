// main.cpp — l2topic, the ROS-1 node used by the iSTEM-Ed ICSEC 2023
// paper "Proposed technique for Data Security with the AES Algorithm
// in Robot Operating System (ROS)".
//
// One executable, multiple modes selected by argv[1]:
//
//   pub      <topic> <type> <data>        — publish once
//   pub100   <topic> <type> <data>        — publish ~100 messages then exit
//   pubimg   <topic>                      — capture camera + publish
//                                            AES-encrypted PNG frames
//   pubimg2  <topic>                      — same as pubimg, but capture
//                                            runs in a producer thread
//                                            with a queue (back-pressured)
//   echo     <topic>                      — subscribe + decrypt + print
//
// The on-wire envelope is JSON:
//   {"Data": "<hex(AES-256-CBC(plaintext))>",
//    "Time": <unix-seconds>,
//    "Type": <int from include/type.h>}
//
// Behaviour preserved verbatim from the paper code; this file has been
// stripped of orphan helpers + dead code paths, function names made
// self-describing, and per-function comments added — see git history
// for the original (much noisier) version.

#include <ros/ros.h>
#include <std_msgs/String.h>
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
#include <opencv2/core.hpp>

#include <queue>
#include <mutex>


// Optional per-call timing dumps to a fixed log path on the paper's
// test rig. Off by default — uncomment to reproduce the paper numbers.
// #define LOG_SUB_TIME
// #define LOG_PUB_TIME

// Camera resolution for pubimg / pubimg2. Exactly one must be active.
// #define _320x240_
// #define _640x480_
// #define _1280x720_
#define _1920x1080_

// When set, the subscriber side decodes + displays the received image
// in an OpenCV window. Off by default to keep the benchmark loop tight.
// #define _SUB_SHOW_IMAGE_

std::queue<cv::Mat> imageQueue;  // Producer queue used by pubimg2.
std::mutex queueMutex;           // (Reserved — current code does not lock.)

pthread_t thread1;               // ThTimer (fps reporter)
pthread_t thread2;               // captureThread (pubimg2 producer)
bool TIME_START = false;
uint32_t CNT_SUB = 0;
uint32_t CNT_PUB = 0;


// AES-256-CBC encrypt `message`, then hex-encode the ciphertext.
// Returns an uppercase hex string. On allocation failure the behaviour
// matches the original paper code (undefined — never observed at the
// sizes used by the experiment).
std::string encryptString(std::string message)
{
    uint8_t *json_msg_enc;
    uint32_t json_msg_enc_mem_size = sizeof(uint8_t) * (int(message.length()) + 1024);
    uint8_t *json_msg_enc_str;
    uint32_t json_msg_enc_str_mem_size = sizeof(uint8_t) * (int(message.length()) + 1024) * 2;

    uint32_t json_msg_enc_size = 0;
    std::string ret_str = "";

    json_msg_enc = (uint8_t *)malloc(json_msg_enc_mem_size);
    memset(json_msg_enc, 0, json_msg_enc_mem_size);

    json_msg_enc_str = (uint8_t *)malloc(json_msg_enc_str_mem_size);
    memset(json_msg_enc_str, 0, json_msg_enc_str_mem_size);

    json_msg_enc_size = aes256Encrypt((uint8_t *)message.c_str(), strlen(message.c_str()), json_msg_enc, json_msg_enc_mem_size);

    ret_str = bytesToHex(json_msg_enc, json_msg_enc_size);

    free(json_msg_enc);
    free(json_msg_enc_str);

    return ret_str;
}

// Inverse of encryptString: hex-decode then AES-256-CBC decrypt.
// Empty input returns an empty string. The result is constructed from
// the decrypted buffer as a C-string, so embedded NULs in the plaintext
// will truncate (intentional — the paper only ships text/hex payloads).
std::string decryptString(std::string encryptMessage)
{
    uint8_t *json_msg_enc;
    uint32_t json_msg_enc_len = 0;
    uint32_t json_msg_enc_mem_size = sizeof(uint8_t) * (int(encryptMessage.length()) + 1024);
    uint8_t *json_msg;
    uint32_t json_msg_mem_size = sizeof(uint8_t) * (int(encryptMessage.length()) + 1024);
    std::string ret_str = "";

    if (encryptMessage.length() == 0) {
        return "";
    }

    json_msg_enc = (uint8_t *)malloc(json_msg_enc_mem_size);
    memset(json_msg_enc, 0, json_msg_enc_mem_size);

    json_msg = (uint8_t *)malloc(json_msg_mem_size);
    memset(json_msg, 0, json_msg_mem_size);

    json_msg_enc_len = hexToBytes((uint8_t *)encryptMessage.c_str(), encryptMessage.length(), json_msg_enc, json_msg_enc_mem_size);
    aes256Decrypt(json_msg_enc, json_msg_enc_len, json_msg, json_msg_mem_size);

    ret_str = std::string((char *)json_msg);

    free(json_msg_enc);
    free(json_msg);

    return ret_str;
}

// Build the wire envelope {"Data":..., "Time":..., "Type":...} where
// Data carries the raw `dataString` (encrypted when `encrypt` is true).
// Used for the String and Image payload types. Hand-rolled stringstream
// (no nlohmann::json) to keep publish latency low — measured in the
// paper as a non-trivial slice of total publish time.
std::string wrapMessageJSON(int type, bool encrypt, std::string dataString)
{
    std::stringstream jsonString;
    std::string jsonDataEnc;

    auto start = std::chrono::high_resolution_clock::now();

    if (encrypt) {
        jsonDataEnc = encryptString(dataString);
    } else {
        jsonDataEnc = dataString;
    }

    #ifdef LOG_PUB_TIME
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        double time_total = duration.count();
        char sys[200];
        sprintf(sys, "echo %.2f >> /media/psf/ROS/report/publish/exetime/time.txt", time_total);
        system(sys);
    #endif

    jsonString << "{\"Data\":\"" << jsonDataEnc << "\",\"Time\":" << (unsigned long)time(NULL) << ",\"Type\":" << type << "}";
    return jsonString.str();
}

// Like wrapMessageJSON, but the inner Data is itself a JSON object
// {"Int32": <i>, "String": <s>} so a single message can carry both an
// int32 and a string. Used by File and Int32 payload types.
std::string wrapPairMessageJSON(int type, bool encrypt, std::string dataString, int32_t dataInt32)
{
    std::stringstream jsonDataString;
    std::stringstream jsonString;
    std::string jsonDataEnc;

    jsonDataString << "{\"Int32\":" << dataInt32 << ",\"String\":\"" << dataString << "\"}";
    if (encrypt) {
        jsonDataEnc = encryptString(jsonDataString.str());
    } else {
        jsonDataEnc = jsonDataString.str();
    }

    jsonString << "{\"Data\":\"" << jsonDataEnc << "\",\"Time\":" << (unsigned long)time(NULL) << ",\"Type\":" << type << "}";
    return jsonString.str();
}

// Read a file from disk and wrap its contents in an encrypted File-type
// envelope. Returns "" if the file can't be opened.
std::string createPubMessageFile(std::string filename)
{
    std::ifstream file_stream;
    std::string line;
    std::string text = "";

    file_stream.open(filename);

    if (!file_stream.is_open()) {
        std::cout << "Unable to open the file " << filename << std::endl;
        return "";
    }

    while (std::getline(file_stream, line)) {
        text = text + line;
    }

    file_stream.close();

    std::cout << "file size = " << text.length() << " byte" << std::endl;
    return wrapPairMessageJSON(TYPE_eString, true, text, 0);
}

// Wrap a string payload in an encrypted String-type envelope.
std::string createPubMessageString(std::string data)
{
    return wrapMessageJSON(TYPE_eString, true, data);
}

// Wrap a hex-encoded image payload in an encrypted Image-type envelope.
std::string createPubImageString(std::string data)
{
    return wrapMessageJSON(TYPE_Image320x240, true, data);
}

// Wrap an int32 payload in an encrypted Int32-type envelope (string
// field is left empty).
std::string createPubMessageInt32(int32_t data)
{
    return wrapPairMessageJSON(TYPE_eInt32, true, "", data);
}


// Decode a hex string into raw bytes, two characters per byte. Any
// non-hex character contributes a zero nibble (mirrors hexCharsToByte).
std::vector<unsigned char> hexStringToVector3(std::string hexString) {
    std::vector<unsigned char> result;
    int cnt = 0;
    uint8_t strh1 = 0;
    uint8_t strh2 = 0;
    for (char c : hexString) {
        if (cnt == 0) {
            strh1 = (uint8_t)c;
            cnt++;
        } else {
            strh2 = (uint8_t)c;
            cnt = 0;
            uint8_t d = hexCharsToByte(strh1, strh2);
            result.push_back(d);
        }
    }

    return result;
}


// Extract the value of the "Data" field from an envelope JSON message
// using a substring scan. Assumes the envelope was built by
// wrapMessageJSON / wrapPairMessageJSON above, so the layout is exactly
//   {"Data":"...","Time":...,"Type":...}
// and a naive find() is sufficient (and significantly faster than a
// real JSON parser at the message sizes used by the experiment).
std::string extractDataFromJson(const std_msgs::String::ConstPtr& msg) {
    std::string jsonString = msg->data;
    std::string startSearch = R"({"Data":")";
    std::string endSearch = R"(","Time":)";
    size_t startIndex = jsonString.find(startSearch) + startSearch.length();
    size_t endIndex = jsonString.find(endSearch);

    return jsonString.substr(startIndex, endIndex - startIndex);
}

// Extract the "Type" integer from an envelope JSON message using a
// hand-rolled state machine. Returns 0 if no "Type":<digit> pair is
// found. Only the first digit is read, which is enough because all
// values in include/type.h are single-digit.
int extractTypeFromJson(const std_msgs::String::ConstPtr& msg) {
    uint32_t slen = msg->data.length();
    uint8_t st = 0;
    for (uint32_t i = 0; i < slen; i++) {
        switch (st) {
            case 0:
                if (msg->data.c_str()[i] == '\"') {
                    st = 1;
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

// ROS subscriber callback for `echo` mode. Recognises the envelope
// produced by createPubMessage*, decrypts the Data field, classifies
// by Type, and prints (or in the image case optionally renders) the
// payload. Messages that don't begin with '{' and end with '}' are
// treated as raw ciphertext and decrypted in place.
void subMessageCallback(const std_msgs::String::ConstPtr& msg)
{
    if (msg->data.length() > 0) {

        if (msg->data.c_str()[0] == '{' && msg->data.c_str()[msg->data.length()-1] == '}') {

            std::string data_json_get = extractDataFromJson(msg);

            auto start_decrypt = std::chrono::high_resolution_clock::now();
            std::string str_data = decryptString(data_json_get);

            #ifdef LOG_SUB_TIME
                auto end_decrypt = std::chrono::high_resolution_clock::now();
                auto duration_decrypt = std::chrono::duration_cast<std::chrono::microseconds>(end_decrypt - start_decrypt);
                double time_execu = duration_decrypt.count();
                char sys[200];
                sprintf(sys, "echo %.2f >> /media/psf/ROS/report/subscribe/exetime/time.txt", time_execu);
                system(sys);
            #endif

            int type;

            // Large payloads are always images — short-circuit the type
            // scan to save a full pass over the (huge) ciphertext.
            if (data_json_get.length() > 10000) {
                type = TYPE_Image320x240;
            } else {
                type = extractTypeFromJson(msg);
            }

            if (type == TYPE_eInt32) {
                printf("data Int32 : %s\r\n", str_data.c_str());
            } else if (type == TYPE_eString) {
                printf("data String : %s, len : %ld\r\n", str_data.c_str(), str_data.length());
            } else if (type == TYPE_File) {
                printf("data String : %s, len : %ld\r\n", str_data.c_str(), str_data.length());
            } else if (type == TYPE_Image320x240) {
                printf("data Image : len : %ld\r\n", str_data.length());

                std::vector<unsigned char> buffer = hexStringToVector3(str_data);

                #ifdef _SUB_SHOW_IMAGE_
                    cv::Mat image = cv::imdecode(buffer, cv::IMREAD_COLOR);
                #endif

                #ifdef _SUB_SHOW_IMAGE_
                if (!image.empty())
                #else
                if (true)
                #endif
                {
                    if (TIME_START == false) {
                        TIME_START = true;
                    }
                    CNT_SUB++;

                    #ifdef _SUB_SHOW_IMAGE_
                        cv::namedWindow("Image Window", cv::WINDOW_NORMAL);
                        cv::imshow("Image Window", image);
                        cv::waitKey(1);
                    #endif
                }
            }
            printf("---\r\n");
        } else {
            std::string plainData = decryptString(msg->data);
            printf("data XXXX : %s, len : %ld\r\n", plainData.c_str(), plainData.length());
            printf("XXX ---\r\n");
        }
    }
}

// Publish `time` messages (or run forever when time == 0) of `type`
// payload `data` on `topic`. Waits for at least one subscriber before
// the first publish. Returns true on natural exit (loop_cnt reached),
// false if the type is unknown or ros::ok() drops out.
bool pubOneMessageX(char *topic, char *type, char *data, uint32_t time)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic), 1000);
    std_msgs::String msg;
    ros::Rate loop_rate(1000);
    ros::Rate loop_rate2(0.5);
    ros::Rate poll_rate(2);
    uint32_t loop_cnt = 0;
    bool first = true;
    while (ros::ok()) {
        if (first) {
            first = false;
            while (publisher.getNumSubscribers() == 0) {
                poll_rate.sleep();
            }
            loop_rate2.sleep();
        }

        if (strncmp(type, "Int32", 5) == 0 || strncmp(type, "int32", 5) == 0) {
            msg.data = createPubMessageInt32(atoi(data));
        } else if (strncmp(type, "String", 6) == 0 || strncmp(type, "string", 6) == 0) {
            msg.data = createPubMessageString(std::string(data));
        } else if (strncmp(type, "File", 4) == 0 || strncmp(type, "file", 4) == 0) {
            auto start = std::chrono::high_resolution_clock::now();
            msg.data = createPubMessageFile(std::string(data));
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "createPubMessageFile time: " << duration.count() << " us" << std::endl;
            char report[200] = {0};
            sprintf(report, "echo %ld >> \"/media/psf/ROS/l2/result/createPub.txt\"", duration.count());
            system(report);
        } else {
            return false;
        }

        if (msg.data != "") {
            publisher.publish(msg);
        }
        ros::spinOnce();
        loop_rate.sleep();

        loop_cnt++;
        if (time > 0) {
            if (loop_cnt > (time - 1)) {
                return true;
            }
        }
    }

    return false;
}

// Publish exactly one message of `type` payload `data` on `topic`,
// after waiting for at least one subscriber. Returns true on success,
// false if the type is unknown.
bool pubOneMessage(char *topic, char *type, char *data)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic), 1000);
    std_msgs::String msg;
    ros::Rate loop_rate(1);
    ros::Rate poll_rate(2);
    while (ros::ok()) {
        while (publisher.getNumSubscribers() == 0) {
            poll_rate.sleep();
        }
        loop_rate.sleep();

        if (strncmp(type, "Int32", 5) == 0 || strncmp(type, "int32", 5) == 0) {
            msg.data = createPubMessageInt32(atoi(data));
        } else if (strncmp(type, "String", 6) == 0 || strncmp(type, "string", 6) == 0) {
            msg.data = createPubMessageString(std::string(data));
        } else if (strncmp(type, "File", 4) == 0 || strncmp(type, "file", 4) == 0) {
            auto start = std::chrono::high_resolution_clock::now();
            msg.data = createPubMessageFile(std::string(data));
            auto end = std::chrono::high_resolution_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
            std::cout << "createPubMessageFile time: " << duration.count() << " us" << std::endl;
        } else {
            return false;
        }

        if (msg.data != "") {
            publisher.publish(msg);
        }
        ros::spinOnce();
        loop_rate.sleep();

        return true;
    }

    return false;
}

// Encode a byte vector as a fixed-width uppercase hex string
// (e.g. {0x5E, 0x2D} -> "5E2D"). Single allocation, hot path for the
// camera publisher.
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

// `pubimg` mode: open the default camera, capture frames at the
// resolution configured at the top of this file, PNG-encode, hex,
// AES-256-CBC-encrypt, wrap in the envelope, and publish — synchronously
// in a tight loop. Returns false only on shutdown (ros::ok() drops).
bool pubCameraStreamEncrypted(char *topic)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic), 1000);
    std_msgs::String msg;
    ros::Rate loop_rate(100000);
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
        capture.set(cv::CAP_PROP_FRAME_WIDTH, 320);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT, 240);
    #elif defined(_640x480_)
        std::cout << "_640x480_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH, 640);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT, 480);
    #elif defined(_1280x720_)
        std::cout << "_1280x720_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH, 1280);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT, 720);
    #elif defined(_1920x1080_)
        std::cout << "_1920x1080_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH, 1920);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT, 1080);
    #else
        std::cout << "Default _320x240_" << std::endl;
        capture.set(cv::CAP_PROP_FRAME_WIDTH, 320);
        capture.set(cv::CAP_PROP_FRAME_HEIGHT, 240);
    #endif

    cv::Mat frame;

    printf("publish started\r\n");

    bool first = true;
    while (nh.ok()) {
        if (first) {
            first = false;
            while (publisher.getNumSubscribers() == 0) {
                ROS_ERROR("Waiting for subscibers");
                poll_rate.sleep();
            }
            poll_rate.sleep();
            TIME_START = true;
        }

        capture >> frame;

        if (frame.empty()) {
            ROS_ERROR_STREAM("Failed to capture image!");
            ros::shutdown();
        }

        std::vector<uchar> buffer;
        cv::imencode(".png", frame, buffer);

        std::string ImageString = vectorToHexString(buffer);

        std::string encimg = createPubImageString(ImageString);

        CNT_PUB++;

        msg.data = encimg;

        if (msg.data != "") {
            publisher.publish(msg);
        }

        ros::spinOnce();
        loop_rate.sleep();
    }
    capture.release();

    return false;
}


// Background producer used by pubCameraStreamEncryptedQueued: grabs
// frames from the default camera at ~10 Hz and pushes them onto
// imageQueue. Runs forever until the process exits.
void * captureThread(void *arguments) {
    cv::VideoCapture cap(0);

    if (!cap.isOpened()) {
        std::cout << "Failed to open camera!" << std::endl;
    } else {
        cap.set(cv::CAP_PROP_FRAME_WIDTH, 320);
        cap.set(cv::CAP_PROP_FRAME_HEIGHT, 240);

        while (true) {
            cv::Mat frame;
            cap >> frame;

            imageQueue.push(frame);
            printf("En Qsize : %ld\r\n", imageQueue.size());

            usleep(100000);
        }
    }
    return static_cast<void*>(0);
}

// `pubimg2` mode: like pubCameraStreamEncrypted, but capture runs in
// captureThread and this loop only consumes from imageQueue, encodes,
// encrypts, and publishes. Useful when capture and encrypt should not
// share the same scheduling slot.
bool pubCameraStreamEncryptedQueued(char *topic)
{
    ros::NodeHandle nh;
    ros::Publisher publisher = nh.advertise<std_msgs::String>(std::string(topic), 1000);
    std_msgs::String msg;
    ros::Rate loop_rate(100000);
    ros::Rate poll_rate(1);

    pthread_create(&thread2, NULL, captureThread, NULL);
    cv::Mat frame;

    bool first = true;

    while (nh.ok()) {
        if (first) {
            first = false;
            while (publisher.getNumSubscribers() == 0) {
                ROS_ERROR("Waiting for subscibers");
                poll_rate.sleep();
            }
            poll_rate.sleep();
            TIME_START = true;
        }

        if (!imageQueue.empty()) {
            frame = imageQueue.front();
            imageQueue.pop();
            printf("De Qsize : %ld\r\n", imageQueue.size());

            if (frame.empty()) {
                ROS_ERROR_STREAM("Failed to capture image!");
                ros::shutdown();
            }

            std::vector<uchar> buffer;
            cv::imencode(".png", frame, buffer);

            std::string ImageString = "";
            char chData[10] = {0};
            for (unsigned char byte : buffer) {
                memset(chData, 0, sizeof(chData));
                sprintf(chData, "%02X", static_cast<uint8_t>(byte));
                ImageString = ImageString + chData;
            }

            printf("hexString.length = %ld\r\n", ImageString.length());
            std::string encimg = createPubImageString(ImageString);

            CNT_PUB++;

            msg.data = encimg;

            if (msg.data != "") {
                publisher.publish(msg);
            }
            ros::spinOnce();
            loop_rate.sleep();
        }
    }

    return false;
}

// Background reporter: once per second, prints publish and subscribe
// rates (instantaneous + running average) once TIME_START flips true.
// Started from main and runs for the lifetime of the process.
void * ThTimer(void *arguments)
{
    double cnt = 0;
    uint32_t pv_sub = 0;
    uint32_t pv_pub = 0;
    uint32_t sub_per_sec = 0;
    uint32_t pub_per_sec = 0;

    double avg_sub_per_sec = 0;
    double avg_pub_per_sec = 0;

    while (1) {
        if (TIME_START) {
            sub_per_sec = CNT_SUB - pv_sub;
            pub_per_sec = CNT_PUB - pv_pub;

            pv_sub = CNT_SUB;
            pv_pub = CNT_PUB;

            cnt++;

            avg_sub_per_sec = double(CNT_SUB) / cnt;
            avg_pub_per_sec = double(CNT_PUB) / cnt;

            if (pub_per_sec > 0) {
                printf("\r\n ----> Publish rate %d fps, AVG %.2f fps <---- \r\n", pub_per_sec, avg_pub_per_sec);
            }
            if (sub_per_sec > 0) {
                printf("\r\n ----> Subscript rate %d fps, AVG %.2f fps <---- \r\n", sub_per_sec, avg_sub_per_sec);
            }
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }
}

// Entry point: parse the mode in argv[1] and dispatch to the matching
// publisher / subscriber helper. The fps reporter (ThTimer) always
// runs in the background.
int main(int argc, char **argv)
{
    char name[50] = {0};
    sprintf(name, "L2Topic_%lu", (unsigned long)time(NULL));
    ros::init(argc, argv, name);

    pthread_create(&thread1, NULL, ThTimer, NULL);

    if (argc < 3) {
        ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
        return 0;
    }

    if (strncmp(argv[1], "pub100", 6) == 0) {
        if (argc < 5) {
            ROS_INFO("Not enough parameter");
            ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
            return 0;
        }

        if (pubOneMessageX(argv[2], argv[3], argv[4], 100)) {
            printf("Publish message success\r\n");
        } else {
            printf("Publish message failed\r\n");
        }
    } else if (strncmp(argv[1], "pubimg2", 7) == 0) {
        pubCameraStreamEncryptedQueued(argv[2]);
    } else if (strncmp(argv[1], "pubimg", 6) == 0) {
        pubCameraStreamEncrypted(argv[2]);
    } else if (strncmp(argv[1], "echo", 4) == 0) {
        ros::NodeHandle nh;
        ros::Subscriber sub = nh.subscribe(std::string(argv[2]), 100000, subMessageCallback);
        ros::spin();
    } else if (strncmp(argv[1], "pub", 3) == 0) {
        if (argc < 5) {
            ROS_INFO("Not enough parameter");
            ROS_INFO("l2topic [ACT] [TOPIC] [TYPE] [DATA]");
            return 0;
        }

        if (pubOneMessage(argv[2], argv[3], argv[4])) {
            printf("Publish message success\r\n");
        } else {
            printf("Publish message failed\r\n");
        }
    }

    return 0;
}
