//
//  main.cpp
//  offsetfinder
//
//  Created by tihmstar on 15.09.17.
//  Copyright © 2017 tihmstar. All rights reserved.
//

#include <stdio.h>
#include <string.h>
extern "C"{
#include "offsetfinder.h"
}

int main(int argc, const char * argv[]) {
    if (argc != 2) {
        printf("Usage: offsetfinder [kernelcache_path]\n");
        return 1;
    }
    
    fprintf(stderr, "(+) Opening \'%s\', found in %s\n", strrchr(argv[1], '/')+1, argv[1]);
    printKernelConfig(argv[1]);
}
