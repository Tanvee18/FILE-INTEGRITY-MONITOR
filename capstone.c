#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/stat.h>
#include <windows.h>



#ifdef _WIN32
#include <windows.h>
#else
#include <unistd.h>
#endif

#define BUFFER_SIZE 1024
#define CHECKSUM_FILE "checksum_store.txt"
#define LOG_FILE "fim_siem_log.txt"
#define ACCESS_LOG "access_log.txt"
#define METADATA_FILE "metadata_store.txt"

void send_desktop_notification(const char *message) {
#ifdef _WIN32
    MessageBox(NULL, message, "FIM Alert", MB_OK | MB_ICONWARNING);
#else
    printf("NOTIFY: %s\n", message);  // Simulate on non-Windows
#endif
}

void log_to_siem(const char *message) {
    FILE *logFile = fopen(LOG_FILE, "a");
    if (!logFile) {
        printf("Error: Cannot open log file!\n");
        return;
    }
    time_t now;
    time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    fprintf(logFile, "[%s] %s\n", timestamp, message);
    fclose(logFile);
}

void track_file_access(const char *filename) {
    FILE *accessLog = fopen(ACCESS_LOG, "a");
    if (!accessLog) {
        printf("Error: Cannot open access log file!\n");
        log_to_siem("ERROR: Cannot open access log file.");
        return;
    }
    time_t now;
    time(&now);
    char *timestamp = ctime(&now);
    timestamp[strlen(timestamp) - 1] = '\0';
    fprintf(accessLog, "[%s] Accessed: %s\n", timestamp, filename);
    fclose(accessLog);
    log_to_siem("File access tracked.");
}

unsigned char compute_checksum(const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        printf("Error: Cannot open file %s\n", filename);
        log_to_siem("ERROR: Cannot open monitored file.");
        return 0;
    }

    unsigned char data[BUFFER_SIZE];
    unsigned char checksum = 0;
    size_t bytesRead;
    while ((bytesRead = fread(data, 1, BUFFER_SIZE, file)) > 0) {
        for (size_t i = 0; i < bytesRead; i++) {
            checksum ^= data[i];
        }
    }
    fclose(file);
    return checksum;
}

void check_metadata_changes(const char *filename) {
    struct stat fileStat;
    if (stat(filename, &fileStat) != 0) {
        printf("Error: Cannot get file metadata for %s\n", filename);
        log_to_siem("ERROR: Cannot get file metadata.");
        return;
    }

    FILE *metaFile = fopen(METADATA_FILE, "r");
    FILE *tempFile = fopen("temp_metadata.txt", "w");
    if (!tempFile) {
        printf("Error: Cannot create temporary metadata file!\n");
        return;
    }

    char storedFile[256];
    unsigned long storedInode, storedPermissions;
    unsigned int storedUid, storedGid;
    long long storedMtime, storedCtime;
    char storedUser[256];  // Username field
    int found = 0;

    char current_user[256] = "UNKNOWN";
#ifdef _WIN32
    DWORD size = sizeof(current_user);
    GetUserName(current_user, &size);
#endif

    if (metaFile) {
        while (fscanf(metaFile, "%s %lu %lu %u %u %lld %lld %s",
                      storedFile, &storedInode, &storedPermissions,
                      &storedUid, &storedGid, &storedMtime, &storedCtime, storedUser) == 8) {

            if (strcmp(storedFile, filename) == 0) {
                found = 1;
                unsigned long currPerms = fileStat.st_mode & 07777;

                int metadata_changed = (
                    storedInode != fileStat.st_ino ||
                    storedPermissions != currPerms ||
                    storedUid != fileStat.st_uid ||
                    storedGid != fileStat.st_gid ||
                    storedMtime != (long long)fileStat.st_mtime ||
                    storedCtime != (long long)fileStat.st_ctime
                );

                if (metadata_changed) {
                    if (strcmp(storedUser, current_user) == 0) {
                        printf("Metadata change ignored: modified by original user (%s).\n", current_user);
                        log_to_siem("Metadata changed by original user; no alert.");
                    } else {
                        printf("WARNING: Metadata change detected for %s\n", filename);
                        log_to_siem("ALERT: Metadata change by a different user!");
                        send_desktop_notification("Metadata change by another user!");
                    }
                } else {
                    printf("Metadata Verified: No changes detected for %s\n", filename);
                    log_to_siem("Metadata Verified: No changes.");
                }

                // Write updated metadata
                fprintf(tempFile, "%s %lu %lu %u %u %lld %lld %s\n", filename,
                        (unsigned long)fileStat.st_ino,
                        currPerms,
                        fileStat.st_uid,
                        fileStat.st_gid,
                        (long long)fileStat.st_mtime,
                        (long long)fileStat.st_ctime,
                        storedUser); // Keep same user
            } else {
                // Copy other lines
                fprintf(tempFile, "%s %lu %lu %u %u %lld %lld %s\n", storedFile,
                        storedInode, storedPermissions, storedUid,
                        storedGid, storedMtime, storedCtime, storedUser);
            }
        }
        fclose(metaFile);
    }

    if (!found) {
        // First time: store username too
        fprintf(tempFile, "%s %lu %lu %u %u %lld %lld %s\n", filename,
                (unsigned long)fileStat.st_ino,
                (unsigned long)(fileStat.st_mode & 07777),
                fileStat.st_uid,
                fileStat.st_gid,
                (long long)fileStat.st_mtime,
                (long long)fileStat.st_ctime,
                current_user);
        printf("New metadata stored for %s (user: %s)\n", filename, current_user);
        log_to_siem("New metadata stored with user info.");
    }

    fclose(tempFile);
    remove(METADATA_FILE);
    rename("temp_metadata.txt", METADATA_FILE);
}



void store_or_verify_checksum(const char *filename, unsigned char new_checksum) {
    FILE *file = fopen(CHECKSUM_FILE, "r+");
    if (!file) {
        file = fopen(CHECKSUM_FILE, "w");
        if (!file) {
            printf("Error: Cannot open checksum storage file!\n");
            log_to_siem("ERROR: Cannot open checksum storage file.");
            return;
        }
    }

    char storedFile[256];
    unsigned int storedChecksum;
    int found = 0;
    long position = 0;

    while (fscanf(file, "%s %x", storedFile, &storedChecksum) != EOF) {
        if (strcmp(storedFile, filename) == 0) {
            found = 1;
            if (storedChecksum == new_checksum) {
                printf("Integrity Verified: The file is unchanged.\n");
                log_to_siem("Integrity Verified: File unchanged.");
            } else {
                printf("WARNING: File Integrity Violation! %s has been modified!\n", filename);
                log_to_siem("ALERT: File integrity violation detected!");
                send_desktop_notification("File integrity violation detected!");
                printf("Old Checksum: %02x, New Checksum: %02x\n", storedChecksum, new_checksum);

                fseek(file, position, SEEK_SET);
                fprintf(file, "%s %02x\n", filename, new_checksum);
                log_to_siem("Checksum updated after tampering detected.");
            }
            break;
        }
        position = ftell(file);
    }

    if (!found) {
        fseek(file, 0, SEEK_END);
        fprintf(file, "%s %02x\n", filename, new_checksum);
        printf("New checksum stored for %s: %02x\n", filename, new_checksum);
        log_to_siem("New checksum stored.");
    }

    fclose(file);
}

int main() {
    char filename[256];
    printf("Enter file name to monitor: ");
    scanf("%255s", filename);

    track_file_access(filename);
    check_metadata_changes(filename);

    unsigned char checksum = compute_checksum(filename);
    printf("Computed Checksum: %02x\n", checksum);

    store_or_verify_checksum(filename, checksum);

    return 0;
}