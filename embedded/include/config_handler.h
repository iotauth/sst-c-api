#ifndef CONFIG_HANDLER_H
#define CONFIG_HANDLER_H

// Changes the current working directory to the location of the given config
// file. If `config_path` is NULL, changes to a default directory.
//
// @param config_path Full or relative path to a config file (can be NULL)
void change_directory_to_config_path(const char* config_path);

// Returns just the filename from a given path, assuming the working directory
// was already changed correctly.
//
// @param path Full or relative path to the config file
// @return Pointer to static buffer containing filename
const char* get_config_path(const char* path);

#endif  // CONFIG_HANDLER_H
