#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "md5.h"

const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings


// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
// Get this function working first!
char * tryWord(char * plaintext, char * hashFilename)
{
    // Hash the plaintext
    char *hash = md5(plaintext, strlen(plaintext));    // Create MD5 hash.
    // Open the hash file
    FILE *h = fopen(hashFilename, "r"); // Open the hashFilename
    if (!h) {
        printf("Can't open file\n");
        free(hash);
        exit(1);
    }

    char word[HASH_LEN + 2];
    // Loop through the hash file, one line at a time.
    while (fgets(word, sizeof(word), h) != NULL) {
        char *nl = strchr(word, '\n');
        if (nl) {
            *nl ='\0';
        }
        // Attempt to match the hash from the file to the
        // hash of the plaintext.
        if (strcmp(hash, word) == 0) {
            fclose(h);
            return hash;
        }
    }
    fclose(h); // Close the open file
    free(hash); // before returning free memory
    return NULL; // If no match return Null
}


int main(int argc, char *argv[])
{
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    // Open the dictionary file for reading.
    FILE *d = fopen(argv[2], "r");
    if (!d) {
        printf("Can't open file\n");
        exit(1);
    }

    char word[PASS_LEN + 2];
    int matched = 0;
    // For each dictionary word, pass it to tryWord, which
    // will attempt to match it against the hashes in the hash_file.
    while (fgets(word, sizeof(word), d)) {
        char *nl = strchr(word, '\n');
        if (nl) {
            *nl ='\0';
        }
        char *found = tryWord(word, argv[1]);

        if (found != NULL)
        {
            printf("%s %s\n", found, word);

            matched++; // Increment count of matched dictionary words

            free(found); // Free memeory from found dictionary words
        }
    }
    // Close the dictionary file.
    fclose(d);

    // Display the number of hashes that were cracked.
    printf("%d hashes cracked\n", matched);
    return 0;
}

