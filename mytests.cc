#include <stdint.h>
#include <stdio.h>
#include <err.h>
#include <getopt.h>
#include <filesystem>
#include <random>
#include <iterator>
#include <iostream>
#include <fstream>
#include<string.h>
#include "lib/data.h"
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include<map>
#include "lib/crypto.h"
#include "lib/prochlo.h"

using namespace std;
namespace fs = filesystem;
using namespace prochlo;

struct ToThreshold {
  PlainThresholderItem plain_thresholder_item;

  // The encrypted crowd ID for the Prochlomation included deep inside
  // |thresholder_item|.
  uint8_t blinded_crowd_id[prochlo::kP256PointLength];
  int occurences;
};
constexpr size_t kPlainBlinderItemLength =
    sizeof(PlainBlinderItem);

void handle_error(const char* msg) {
    perror(msg);
    exit(255);
}

int compare(uint8_t* existing, int exlen, uint8_t* test,int tlen){
    if(exlen != tlen){return -1;}
    for (int ii=0; ii<exlen; ii++){

        if(*(existing+ii) != *(test+ii)){return -1;}
    }
    return 1;
}

void print_hex(uint8_t* msg,int len) {
    int i;
    for (i=0;i<len;i++) {
        printf("0x%02hhx ", *(msg+i));
    }
    printf("\n");
}

int main(int argc, char* argv[]){

    auto configuration = std::unique_ptr<Configuration>(new Configuration());
    configuration->blinder_key_file="etc/key1.pub";
    configuration->thresholder_key_file="etc/key2.pub";
    configuration->analyzer_key_file="etc/key3.pub";
    configuration->blinder_private_key_file="etc/key1.pem";
    configuration->thresholder_private_key_file="etc/key2.pem";
    configuration->analyzer_private_key_file="etc/key3.pem";
    configuration->output_file="test_out.dat";
    
    Prochlo prochlo;

    if (!prochlo.set_configuration(std::move(configuration))) {
    warn("set_configuration()");
    return -1;
    }
    
    if (!prochlo.setup_output()) {
        warn("setup_output()");
        return -1;
    }
    int N =5000;

	const char *filepath = to_string(N)+".dat";

     int fd = open(filepath, O_RDONLY, (mode_t)0600);
	
    if (fd == -1)
    {
        perror("Error opening file for writing");
        exit(EXIT_FAILURE);
    }        
    
    struct stat fileInfo = {0};
    
    if (fstat(fd, &fileInfo) == -1)
    {
        perror("Error getting the file size");
        exit(EXIT_FAILURE);
    }
    
    if (fileInfo.st_size == 0)
    {
        fprintf(stderr, "Error: File is empty, nothing to do\n");
        exit(EXIT_FAILURE);
    }
    
    //printf("File size is %ji\n", (intmax_t)fileInfo.st_size);
    
    void *filemap = mmap(0, fileInfo.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (filemap == MAP_FAILED)
    {
        close(fd);
        perror("Error mmapping the file");
        exit(EXIT_FAILURE);
    }
    
    BlinderItem* blinder_items_;
    blinder_items_ = reinterpret_cast<BlinderItem*>(filemap);
    ToThreshold histogram[5000];

    int T = 2;
    int j=0;
    unsigned long total = 0;

	for( int i =0; i<N;i++){
        //printf("%d",i);
		BlinderItem b= blinder_items_[i];
		
        //Blinder operation
        PlainBlinderItem plain_blinder_item;
        prochlo.crypto_.DecryptBlinder(b,&plain_blinder_item);
        BIGNUM* one = BN_new(); //secret used to blind
        BN_one(one);
        prochlo.crypto_.BlindEncryptedBlindableCrowdId(&plain_blinder_item.encoded_crowd_id,*one);
        //Thresholder operation
        PlainThresholderItem plain_thresholder_item;
        prochlo.crypto_.DecryptThresholder(plain_blinder_item.thresholder_item,&plain_thresholder_item);
        uint8_t blinded_crowd_id[prochlo::kP256PointLength];
        prochlo.crypto_.DecryptBlindedCrowdId(&plain_blinder_item.encoded_crowd_id,
                                         *EC_KEY_get0_private_key(EVP_PKEY_get0_EC_KEY(prochlo.crypto_.private_thresholder_key_)),
                                         blinded_crowd_id);
        
        bool found=false;
        //print_hex(&blinded_crowd_id[0],sizeof(blinded_crowd_id));
        int jj =0;
        for (auto record : histogram){
            if(compare(&record.blinded_crowd_id[0],sizeof(record.blinded_crowd_id),&blinded_crowd_id[0],sizeof(blinded_crowd_id))==1){
                //printf("found in array: \n");
                //print_hex(&record.blinded_crowd_id[0],sizeof(record.blinded_crowd_id));
                //printf("compare result: %d\n",compare(&record.blinded_crowd_id[0],sizeof(record.blinded_crowd_id),&blinded_crowd_id[0],sizeof(blinded_crowd_id)));
                //printf("previous occurences:%d \n",record.occurences);
                if(record.occurences<T-1){
                    histogram[jj].occurences++;
                    //printf("%d",record.occurences);
                }else{
                    histogram[jj].occurences=0;
                    //analyzer operation
                    PlainAnalyzerItem plain_analyzer_item;
                    //printf("sending to analyser\n");
                    prochlo.crypto_.DecryptAnalyzer(record.plain_thresholder_item.analyzer_item,&plain_analyzer_item);
                    printf("%s\n",plain_analyzer_item.prochlomation.data);
                    total=total + 50;
                }
                //printf("crowd ID: ");
                //print_hex(&record.blinded_crowd_id[0],sizeof(record.blinded_crowd_id));
                //printf("occurences:%d \n \n",histogram[jj].occurences);
                found=true;
                break;
            }
            jj++;
        }
        if(!found){
            ToThreshold thisItem;
            memcpy(&thisItem.blinded_crowd_id,&blinded_crowd_id,prochlo::kP256PointLength);
            memcpy(&thisItem.plain_thresholder_item,&plain_thresholder_item,prochlo::kPlainThresholderItemLength);
            thisItem.occurences=1;
            histogram[j]=thisItem;
            j++;
        }
	}
    printf("%lu \n",total);
/*    for (record: histogram){
        if( < T){
            it = histogram.erase(it);
        }else{
            ++it;
        }

    }
*/
    

    // Don't forget to free the mmapped memory
    if (munmap(filemap, fileInfo.st_size) == -1)
    {
        close(fd);
        perror("Error un-mmapping the file");
        exit(EXIT_FAILURE);
    }

    // Un-mmaping doesn't close the file, so we still need to do that.
    close(fd);
    
    return 0;
}