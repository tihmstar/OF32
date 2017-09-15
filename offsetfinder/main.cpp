//
//  main.cpp
//  offsetfinder
//
//  Created by tihmstar on 15.09.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <iostream>
#include <string.h>
extern "C"{
#include "offsetfinder.h"
#include <libfragmentzip/libfragmentzip.h>
#include <curl/curl.h>
}
#include <libipatcher/libipatcher.hpp>
#include "jssy.hpp"
#include <vector>
#include <assert.h>

using namespace std;

size_t write_data(void *ptr, size_t size, size_t nmemb, FILE *stream) {
    size_t written = fwrite(ptr, size, nmemb, stream);
    return written;
}

int main(int argc, const char * argv[]) {
    if (argc < 2) {
        printf("Usage: offsetfinder [buildID] (device1,device2...)\n");
        return 1;
    }
    CURL *curl;
    FILE *fp;
    CURLcode res;
    char outfilename[FILENAME_MAX] = "/tmp/offsetfindertmp.json";
    curl = curl_easy_init();
    if (!curl) {
        fprintf(stderr, "(!) Failed to creat firmwares.json\n");
        return 1;
    }
    fp = fopen(outfilename,"wb");
    curl_easy_setopt(curl, CURLOPT_URL, "https://api.ipsw.me/v2.1/firmwares.json");
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_data);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
    fprintf(stderr, "(+) Downloading firmwares.json\n");
    res = curl_easy_perform(curl);
    curl_easy_cleanup(curl);
    fclose(fp);
    
    fprintf(stderr, "(+) Parsing firmwares.json\n");
    jssycpp::jssy firmwares(outfilename);
    
    vector<pair<string, string>> devlinks;
    for (auto dev : firmwares["devices"]){
        for (int i=2; i< argc; i++){
            if (dev.stringValue().compare(argv[i]) == 0) goto okok;
        }
        continue;
    okok:
        for (auto devfw : dev.subval()["firmwares"]){
            if (devfw["buildid"].stringValue().compare(argv[1]) == 0){
                devlinks.push_back({dev.stringValue(),devfw["url"].stringValue()});
            }
        }
    }
    int hasone = 0;
    for (auto link:devlinks){
        fprintf(stderr, "(+) Opening Firmware for %s\n",link.first.c_str());
        fragmentzip_t * fz = fragmentzip_open(link.second.c_str());
        
        assert(fz);
        
        fragmentzip_cd* cd = fz->cd;
        for(int i = 0; i < fz->cd_end->cd_entries; i++) {
            if (cd->len_filename > strlen("kernelcache") && !strncmp(cd->filename,"kernelcache",strlen("kernelcache"))){
                fprintf(stderr,"(+) Downloading %.*s\n",cd->len_filename,cd->filename);
                char fname[cd->len_filename+1];
                strncpy(fname, cd->filename, cd->len_filename);
                fname[cd->len_filename] = 0;
                assert(!fragmentzip_download_file(fz, fname, "/tmp/offsetfinderkernel", NULL));
                goto okkk;
            }
            cd = fragmentzip_nextCD(cd);
        }
        fprintf(stderr, "(!) Failed to find kernel for %s!\n",link.first.c_str());
        return -2;
    okkk:
        fragmentzip_close(fz);
        fprintf(stderr, "(+) Getting Firmware key\n");
        libipatcher::fw_key key;
        try{
            key = libipatcher::getFirmwareKey(link.first, {argv[1]}, "Kernelcache");
        }catch(std::exception &e){
            fprintf(stderr, "(!) Failed to get firmware key for %s!\n",link.first.c_str());
            printf("\n#ERROR failed_to_find_firmware_key_for_%s\n",link.first.c_str());
            continue;
        }
        
        FILE *enckf = fopen("/tmp/offsetfinderkernel", "r");
        char *kbuf = NULL;
        size_t ksize = 0;
        
        fseek(enckf, 0, SEEK_END);
        ksize = ftell(enckf);
        fseek(enckf, 0, SEEK_SET);
        fclose(enckf);
        
        kbuf = (char*)malloc(ksize);
        
        std::pair<char*,size_t> deckernel;
        
        try{
            deckernel = libipatcher::extractKernel(kbuf, ksize, key);
        }catch(std::exception &e){
            free(kbuf);
            fprintf(stderr, "(!) Failed to get firmware key for %s!\n",link.first.c_str());
            printf("\n#ERROR failed_to_find_firmware_key_for_%s\n",link.first.c_str());
            continue;
        }
        free(kbuf);
        
        
        macho_map_t *map = (macho_map_t *)malloc(sizeof(macho_map_t));
        map->map_data = deckernel.first;
        map->map_magic = MACHO_MAP_MAGIC;
        map->map_size = (mach_vm_size_t)deckernel.second;
        map->unique_id = (uint32_t)(((uint64_t)map << 32) >> 32);
        
        fprintf(stderr, "(+) Finding offsets\n");
        printf("\n// %s\n",link.first.c_str());
        if (hasone) printf("else ");
        printKernelConfig(map);
        fprintf(stderr, "(+) Done %s\n",link.first.c_str());
        fflush(stdout);
        
        free(map);
        hasone = 1;
    }
    
    return 0;
}
