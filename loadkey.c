
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <dirent.h>

#include "loadkey.h"

// Load a station key and public key from a single file
int td_load_single_station_key(const char *fname, uint8_t stationkey[TD_KEYLEN_BYTES], uint8_t pubkey[TD_KEYLEN_BYTES])
{
    FILE *fin = fopen(fname, "r");
    int rc;
    char extra;

    if (!fin)
        return -1;

    rc = fread(stationkey, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1)
    {
        fclose(fin);
        return -2;
    }

    rc = fread(pubkey, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1)
    {
        fclose(fin);
        return -3;
    }

    // Check for any extra data in the file (optional step)
    if (1 == fread(&extra, sizeof(extra), 1, fin))
    {
        // Handle the extra data if necessary
        // TODO: Decide if you want to return an error or process the extra data
    }

    fclose(fin);
    return 0;
}

// Function to load station keys from a file or directory
int td_load_station_keys(const char *path, uint8_t stationkeys[][TD_KEYLEN_BYTES], uint8_t pubkeys[][TD_KEYLEN_BYTES], uint8_t *key_count, int max_keys)
{
    struct stat path_stat;
    if (stat(path, &path_stat) != 0)
    {
        return -1; // Error accessing the path
    }

    if (S_ISDIR(path_stat.st_mode))
    {
        DIR *dir = opendir(path);
        if (!dir)
        {
            return -2; // Failed to open directory
        }

        struct dirent *entry;
        int count = 0;
        while ((entry = readdir(dir)) != NULL && count < max_keys)
        {
            char filepath[1024];
            snprintf(filepath, sizeof(filepath), "%s/%s", path, entry->d_name);

            if (td_load_single_station_key(filepath, stationkeys[count], pubkeys[count]) == 0)
            {
                count++;
            }
        }
        closedir(dir);
        *key_count = count;
        return (count > 0) ? 0 : -3; // Return 0 if at least one key is loaded, otherwise error
    }
    else
    {
        if (td_load_single_station_key(path, stationkeys[0], pubkeys[0]) == 0)
        {
            *key_count = 1;
            return 0;
        }
        else
        {
            return -4; // Error loading key from file
        }
    }
}

// Load a public key from the given file. Returns 0 if successful, < 0 otherwise
int td_load_public_key(const char *fname, uint8_t keybuf[TD_KEYLEN_BYTES])
{
    FILE *fin = fopen(fname, "r");
    int rc;
    char extra;

    if (!fin)
        return -1;

    rc = fread(keybuf, TD_KEYLEN_BYTES, 1, fin);
    if (rc != 1)
    {
        fclose(fin);
        return -2;
    }

    // See if there's anything more in the file, which might indicate that it's
    // a proper key file.
    if (1 != fread(&extra, sizeof(extra), 1, fin))
    {
        // TODO: ?
    }
    fclose(fin);

    return 0;
}

// Print a key to stdout, in hex.
void td_print_key(const uint8_t key[TD_KEYLEN_BYTES])
{
    unsigned int i;
    for (i = 0; i < TD_KEYLEN_BYTES; i++)
        printf("%.2x", key[i]);
}

// Create a newly-malloc'ed string representation of a key
char *td_key2str(const uint8_t key[TD_KEYLEN_BYTES])
{
    char *buf = malloc((2 * TD_KEYLEN_BYTES) + 1);

    unsigned int i;
    for (i = 0; i < TD_KEYLEN_BYTES; i++)
        sprintf(&buf[2 * i], "%.2x", key[i]);

    buf[2 * TD_KEYLEN_BYTES] = 0;
    return buf;
}
