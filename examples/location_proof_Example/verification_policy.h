#ifndef VERIFICATION_POLICY_H
#define VERIFICATION_POLICY_H

char *load_verification_policy(const char *path);
void free_verification_policy(char *policy);

#endif