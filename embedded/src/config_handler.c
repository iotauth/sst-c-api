#include <fcntl.h>
#include <libgen.h>
#include <linux/limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void change_directory_to_config_path(const char* config_path) {
    char original_dir[PATH_MAX];
    char new_dir[PATH_MAX];

    if (getcwd(original_dir, sizeof(original_dir)) == NULL) {
        perror("Fatal: Could not determine current working directory");
        exit(1);
    }

    if (config_path) {
        // A path was provided. Change to the directory of the config file.
        char* path_copy = strdup(config_path);
        if (!path_copy) {
            perror("strdup failed");
            exit(1);
        }

        char* dir = dirname(path_copy);
        if (chdir(dir) != 0) {
            perror("Failed to change directory to config file location");
            free(path_copy);
            exit(1);
        }

        // Now that we are in the correct directory, get the CWD to print it.
        if (getcwd(new_dir, sizeof(new_dir)) == NULL) {
            perror("Fatal: Could not determine new working directory");
            free(path_copy);
            exit(1);
        }
        printf("Changed directory from '%s' to '%s'\n", original_dir, new_dir);
        free(path_copy);
    } else {
        // No path provided, change to the default directory.
        const char* config_dir_relative = "../../receiver";
        if (chdir(config_dir_relative) != 0) {
            perror("Could not switch to default config directory");
            fprintf(stderr, "Failed to find default config ('%s') from your current location:\n", config_dir_relative);
            exit(1);
        }

        if (getcwd(new_dir, sizeof(new_dir)) == NULL) {
            perror("Fatal: Could not determine new working directory");
            exit(1);
        }

        printf("Changed directory from '%s' to '%s'\n", original_dir, new_dir);
    }
}

const char* get_config_path(const char* path) {
    // This function now returns only the filename part of the path,
    // because change_directory_to_config_path() has already moved us
    // into the correct directory.
    static char filename[PATH_MAX];

    if (path) {
        // A path was provided, extract the filename.
        char* path_copy = strdup(path);
        if (!path_copy) {
            perror("strdup failed");
            exit(1);
        }

        char* bname = basename(path_copy);
        // Copy the basename to our static buffer so it persists after free.
        strncpy(filename, bname, sizeof(filename) - 1);
        filename[sizeof(filename) - 1] = '\0';

        free(path_copy);
        return filename;
    } else {
        // No path provided, use the default filename. After chdir, this is correct.
        return "sst.config";
    }
}
