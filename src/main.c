#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <sys/time.h>
#include <ctype.h>
#include <unistd.h>
#include <time.h>

#include <curl/curl.h>

#include <ldap.h>
#include <lber.h>

// For some reason, these functions are not defined in the header file
//  Gosh, I hope I'm using buggy deprecated stuff.

/// Synchronous LDAP bind operation
int ldap_bind_s(LDAP *ld, const char *who, const char *cred, int method);

/// Synchronoud LDAP unbind operation
int ldap_unbind_s(LDAP *ld);

char **ldap_get_values(LDAP *ld, LDAPMessage *entry, char *attr);

void ldap_value_free(char **vals);

/// Global timeout for LDAP operations
struct timeval timeout = {
    .tv_sec = 5,
    .tv_usec = 0,
};

const char *service_account_cn = "service_account";

/// @brief Exit the program with a status code
/// @param status The status code to exit with
/// @return void
void print_and_quit(int status)
{
    printf("FAIL! Exit code: %d\n", status);
    exit(0);
}

/// @brief Create a password reset link and email it to the user
void email_user()
{
    // This is called as a cgi post request, so we need to read the username from the post data
    //  and then look up the user's email address in LDAP.
    // The post data should be supplied in stdin.

    // For now, just print stdin to stdout for debugging purposes.

    // Read the length of the post data from the environment.
    char *content_length_str = getenv("CONTENT_LENGTH");
    if (content_length_str == NULL)
    {
        printf("No content length\n");
        exit(1);
    }

    // Convert the content length to an integer
    int content_length = atoi(content_length_str);

    // Allocate a buffer to read the post data into
    char *post_data = malloc(content_length + 1);
    if (post_data == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }

    // Read the post data from stdin
    int bytes_read = fread(post_data, 1, content_length, stdin);
    if (bytes_read != content_length)
    {
        printf("Failed to read post data\n");
        exit(1);
    }

    // Null-terminate the post data
    post_data[content_length] = 0;

    // unescape the post data
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        printf("Failed to initialize curl\n");
        exit(1);
    }

    // We need to save the encoded server parameter to use it later.
    char *server_param = strstr(post_data, "server=");
    if (server_param == NULL)
    {
        printf("No server parameter found\n");
        exit(1);
    }
    server_param += strlen("server=");

    int post_data_decoded_len;
    char *post_data_decoded = curl_easy_unescape(curl, post_data, content_length, &post_data_decoded_len);
    if (post_data_decoded == NULL)
    {
        printf("Failed to decode post data\n");
        exit(1);
    }

    // Now, the post data is in the format "userid=<username>&email=<email>&ldap_uri=<server_uri>+<server_basedn>"
    //  We need to extract the username, email, and the ldap_uri uri and base dn from this string.

    // Find the username
    char *username = strstr(post_data_decoded, "userid=");
    if (username == NULL)
    {
        printf("No username found\n");
        exit(1);
    }
    username += strlen("userid=");
    char *username_end = strchr(username, '&');

    if (username_end == NULL)
    {
        printf("No username end found\n");
        exit(1);
    }

    // Find the email
    char *email = strstr(post_data_decoded, "email=");
    if (email == NULL)
    {
        printf("No email found\n");
        exit(1);
    }
    email += strlen("email=");
    char *email_end = strchr(email, '&');

    if (email_end == NULL)
    {
        printf("No email end found\n");
        exit(1);
    }

    // Find the ldap_uri
    char *ldap_uri = strstr(post_data_decoded, "server=");
    if (ldap_uri == NULL)
    {
        printf("No server found\n");
        exit(1);
    }
    ldap_uri += strlen("server=");
    char *server_end = strchr(ldap_uri, '+');

    if (server_end == NULL)
    {
        printf("No server end found\n");
        exit(1);
    }

    char *ldap_base = server_end + 1;

    // Add the null terminators
    *username_end = 0;
    *email_end = 0;
    *server_end = 0;

    // Now, we have the username, server uri, and base dn.
    // We need to look up the user's email address in LDAP and send them a password reset link.

    printf("Finding user with the following details:\n");
    printf("username: %s\n", username);

    // Now, we need to determine the bind dn and password for the service account.
    char *bind_dn = malloc(strlen("cn=") + strlen(service_account_cn) + strlen(",") + strlen(ldap_base) + 1);
    if (bind_dn == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    sprintf(bind_dn, "cn=%s,%s", service_account_cn, ldap_base);

    // The password lives in a file in the working directory called ".password.service_account"
    FILE *password_file = fopen(".password.service_account", "r");
    if (password_file == NULL)
    {
        printf("Failed to open password file\n");
        exit(1);
    }

    // Read one line from the password file
    char bind_pw[255];
    if (fgets(bind_pw, 255, password_file) == NULL)
    {
        printf("Failed to read password\n");
        exit(1);
    }

    // Remove the newline from the password
    char *newline = strchr(bind_pw, '\n');
    if (newline != NULL)
    {
        *newline = 0;
    }

    // Initialize the LDAP connection
    LDAP *ld;
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    int status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to bind to LDAP\n");
        print_and_quit(status);
    }

    printf("Bind successful\n");

    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
    LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    char ldap_search_str[255] = {
        0,
    };

    sprintf(ldap_search_str, "(SamAccountName=%s)", username);

    status = ldap_search_ext_s(
        ld,
        ldap_base,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"mail", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    printf("Getting email address to verify\n");
    char *ldap_email = *ldap_get_values(ld, *res, "mail");
    if (ldap_email == NULL)
    {
        printf("Email not found\n");
        print_and_quit(1);
    }

    // Check to see if ldap_email is a substring of email
    if (strstr(email, ldap_email) == NULL)
    {
        printf("Email %s does not match ldap_email %s\n", email, ldap_email);
        print_and_quit(1);
    }

    printf("Email successfully verified.\n");

    status = ldap_unbind_s(ld);
    // printf("unbind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }
    printf("Successfully unbound from LDAP\n");

    printf("\n\n\nSending email to %s\n", email);

    // Generate a random password reset token - alphanumeric, 16 characters long
    char token[17];
    for (int i = 0; i < 16; i++)
    {
        token[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 62];
    }
    token[16] = 0;

    // Get our FQDN to build the URL
    char fqdn[255];
    gethostname(fqdn, 255);

    char reset_link[512];
    sprintf(reset_link, "http://%s/cgi-bin/set-password?token=%s&username=%s&server=%s", fqdn, token, username, server_param);

    // Now, we need to send an email to the user with a password reset link.
    // We'll do this by calling to the shell to run the sendmail command.

    // Create a temporary file called ".%s", where %s is the username
    char email_filename[255];
    sprintf(email_filename, ".%s", username);
    FILE *email_file = fopen(email_filename, "w");
    if (email_file == NULL)
    {
        printf("Failed to open %s for writing\n", email_filename);
        print_and_quit(1);
    }

    // To the email contents file, write the subject
    fprintf(email_file, "Subject: Password reset\n\n");

    // Write the body of the email
    fprintf(email_file, "Hello %s,\n\n", username);
    fprintf(email_file, "You have requested a password reset. Please go to the following URL to reset your password:\n\n");
    fprintf(email_file, "%s\n\n", reset_link);

    fclose(email_file);

    // Now, we need to send the email. Do this by calling the sendmail command.
    // Use popen to run the sendmail command and write the email contents to it,
    // and write its stdout to our stdout.
    char sendmail_command[667];
    sprintf(sendmail_command, "/usr/sbin/sendmail < %s %s", email_filename, email);

    FILE *sendmail_output = popen(sendmail_command, "r");
    if (sendmail_output == NULL)
    {
        printf("Failed to run sendmail\n");
        print_and_quit(1);
    }

    printf("<debug output<\n");
    // Read the output of the sendmail command and write it to stdout
    char sendmail_output_buf[255];
    while (fgets(sendmail_output_buf, 255, sendmail_output) != NULL)
    {
        printf("%s", sendmail_output_buf);
    }
    pclose(sendmail_output);

    printf(">done>\n");
}

/// @brief Set the password for a user via LDAP
void set_password()
{
    // This is called as a CGI get request, with parameters in the following order:
    //  token, user, server.
    char *query_string = getenv("QUERY_STRING");
    if (query_string == NULL)
    {
        printf("No query string\n");
        print_and_quit(1);
    }

    // Find the token
    char *token = strstr(query_string, "token=");
    if (token == NULL)
    {
        printf("No token found\n");
        print_and_quit(1);
    }
    token += strlen("token=");
    char *token_end = strchr(token, '&');

    if (token_end == NULL)
    {
        printf("No token end found\n");
        print_and_quit(1);
    }

    // Find the username
    char *username = strstr(query_string, "username=");
    if (username == NULL)
    {
        printf("No username found\n");
        print_and_quit(1);
    }
    username += strlen("username=");
    char *username_end = strchr(username, '&');

    if (username_end == NULL)
    {
        printf("No username end found\n");
        print_and_quit(1);
    }

    // Find the server
    char *server = strstr(query_string, "server=");
    if (server == NULL)
    {
        printf("No server found\n");
        print_and_quit(1);
    }
    server += strlen("server=");

    // Add the null terminator for the username and token
    *username_end = 0;
    *token_end = 0;

    // Now, we have the username and token.

    // For server, we need to urldecode it just like we did for the post data in email_user()
    CURL *curl = curl_easy_init();
    if (curl == NULL)
    {
        printf("Failed to initialize curl\n");
        print_and_quit(1);
    }

    int server_len = strlen(server);
    char *server_decoded = curl_easy_unescape(curl, server, server_len, &server_len);
    if (server_decoded == NULL)
    {
        printf("Failed to decode server\n");
        print_and_quit(1);
    }

    // Now, we have the decoded server string.

    // We need to extract the server uri and base dn from this string.
    char *ldap_uri = server_decoded;
    char *ldap_uri_end = strchr(server_decoded, '+');
    if (ldap_uri_end == NULL)
    {
        printf("No server uri end found\n");
        print_and_quit(1);
    }

    char *ldap_base = ldap_uri_end + 1;

    // Add the null terminator for the server uri
    *ldap_uri_end = 0;

    // First, check to see if there's a file called ".%s" in the working directory, where %s is the username.
    // If there is, read the contents of the file and see if the token string is located anywhere in the file.
    // If it is, then we can set the password for the user.

    char email_filename[255];
    sprintf(email_filename, ".%s", username);
    FILE *email_file = fopen(email_filename, "r");
    if (email_file == NULL)
    {
        printf("Failed to open %s for reading\n", email_filename);
        printf("Are you sure you have an open password reset request?\n");
        // Get our FQDN to build the URL
        char fqdn[255];
        gethostname(fqdn, 255);
        printf("Open a new one at http://%s/\n", fqdn);
        exit(0);
    }

    // Read the contents of the email file
    char email_contents[4096];
    int email_contents_len = fread(email_contents, 1, 4096, email_file);
    if (email_contents_len == 4096)
    {
        printf("Email contents too long\n");
        print_and_quit(1);
    }

    // Null-terminate the email contents
    email_contents[email_contents_len] = 0;

    // Check to see if the token is in the email contents
    if (strstr(email_contents, token) == NULL)
    {
        printf("Token not found in email contents\n");
        print_and_quit(1);
    }

    // Now, look up the DN for the user and set their password.
    // TODO: For now, this is hardcoded for AD.

    // Now, we need to determine the bind dn and password for the service account.
    char *bind_dn = malloc(strlen("cn=") + strlen(service_account_cn) + strlen(",") + strlen(ldap_base) + 1);
    if (bind_dn == NULL)
    {
        printf("Failed to allocate memory\n");
        exit(1);
    }
    sprintf(bind_dn, "cn=%s,%s", service_account_cn, ldap_base);

    // The password lives in a file in the working directory called ".password.service_account"
    FILE *password_file = fopen(".password.service_account", "r");
    if (password_file == NULL)
    {
        printf("Failed to open password file\n");
        exit(1);
    }

    // Read one line from the password file
    char bind_pw[255];
    if (fgets(bind_pw, 255, password_file) == NULL)
    {
        printf("Failed to read password\n");
        exit(1);
    }

    // Remove the newline from the password
    char *newline = strchr(bind_pw, '\n');
    if (newline != NULL)
    {
        *newline = 0;
    }

    // Initialize the LDAP connection
    LDAP *ld;
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    int status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to bind to LDAP\n");
        print_and_quit(status);
    }

    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
    LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    char ldap_search_str[255] = {
        0,
    };

    sprintf(ldap_search_str, "(SamAccountName=%s)", username);

    // We're going to create a new password, with 16 random alphanumeric characters,
    //  followed by Aa1! to cheese the password policy.
    // That length is going to be 16 (random) + 4 (fixed) + 1 (null terminator) = 21
    char *newpasswd = malloc(21);

    for (int i = 0; i < 16; i++)
    {
        newpasswd[i] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"[rand() % 62];
    }

    newpasswd[16] = 'A';
    newpasswd[17] = 'a';
    newpasswd[18] = '1';
    newpasswd[19] = '!';
    newpasswd[20] = 0;

    status = ldap_search_ext_s(
        ld,
        ldap_base,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"distinguishedName", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to search for %s\n", ldap_search_str);
        print_and_quit(status);
    }

    char *user_dn = *ldap_get_values(ld, *res, "distinguishedName");
    if (user_dn == NULL)
    {
        printf("User not found\n");
        print_and_quit(1);
    }

    // This is AD:

    // The AD unicodePwd attribute is very fiddly. We'll need to do the following:
    // 1. Enclose the password in quotes
    // 2. Convert the password to UTF-16LE (No BOM)
    // 3. Send the password as a binary value in an LDAP modify operation

    // So, first, add the quotes.
    char *newpasswd_quoted = malloc(strlen(newpasswd) + 3); // 2 characters for the quotes, 1 for the null terminator
    newpasswd_quoted[0] = '"';
    strcpy(newpasswd_quoted + 1, newpasswd);
    newpasswd_quoted[strlen(newpasswd) + 1] = '"';
    newpasswd_quoted[strlen(newpasswd) + 2] = 0;

    // Then, convert the quoted password to UTF-16LE (No BOM)
    uint8_t *newpasswd_utf16le = malloc(strlen(newpasswd_quoted) * 2); // 2 bytes per character, no null terminator or BOM

    for (int i = 0; i < (int)strlen(newpasswd_quoted); i++)
    {
        newpasswd_utf16le[i * 2] = newpasswd_quoted[i];
        newpasswd_utf16le[i * 2 + 1] = 0;
    }

    struct berval passwd_berval = {
        .bv_len = strlen(newpasswd_quoted) * 2,
        .bv_val = (char *)newpasswd_utf16le,
    };

    // Change the password
    LDAPMod mod = {
        .mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, // Binary replacement operation
        .mod_type = "unicodePwd",
        .mod_vals.modv_bvals = (struct berval *[]){&passwd_berval, NULL},
    };

    LDAPMod *mods[] = {&mod, NULL};

    status = ldap_modify_ext_s(
        ld,
        user_dn,
        mods,
        NULL,
        NULL);

    if (status != LDAP_SUCCESS)
    {
        printf("user modify failed, status: %d: %s\n", status, ldap_err2string(status));
        print_and_quit(status);
    }

    // printf("New password for %s: %s\n", username, newpasswd);
    printf("%s\n", newpasswd);

    // Now, delete the email contents file '.%s' where %s is the username
    if (remove(email_filename) != 0)
    {
        printf("Failed to delete email contents file %s\n", email_filename);
        print_and_quit(1);
    }
}

void debug()
{
    /// Buffer for a single LDAP search result
    // unsigned char ldap_search_result_buf[sizeof(LDAPMessage *) * 5];
    // LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    // Read environment variables to decide what to do
    const char *bind_dn = getenv("CPWD_BIND_DN");        // e.g. "cn=admin,dc=example,dc=com"
    const char *bind_pw = getenv("CPWD_BIND_PW");        // e.g. "password"
    const char *ldap_uri = getenv("CPWD_LDAP_URI");      // e.g. "ldap://localhost:389"
    const char *ldap_base = getenv("CPWD_LDAP_BASE");    // e.g. "dc=example,dc=com"
    const char *username = getenv("CPWD_USERNAME");      // e.g. "ldaptest"
    const char *newpasswd = getenv("CPWD_PASSWORD_NEW"); // e.g. "passwordAa1!";
    const char *email = getenv("CPWD_EMAIL");            // e.g. "ahatfield@team17.devon.swccdc.com"

    // Exit if any required environment variables are missing
    if (!bind_dn || !bind_pw || !ldap_uri || !ldap_base || !username || !newpasswd || !email)
    {
        printf("Missing required environment variables\n");
        exit(1);
    }

    //////////////////////////////////////////////////////////////
    ////// debug for email-user

    printf("Connecting to LDAP as %s\n", bind_dn);
    // Initialize the LDAP connection
    LDAP *ld;
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    int status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to bind to LDAP\n");
        print_and_quit(status);
    }

    printf("Bind successful\n");

    /// Buffer for a single LDAP search result
    unsigned char ldap_search_result_buf[sizeof(LDAPMessage *)];
    LDAPMessage **res = (LDAPMessage **)ldap_search_result_buf;

    char ldap_search_str[255] = {
        0,
    };

    sprintf(ldap_search_str, "(SamAccountName=%s)", username);

    status = ldap_search_ext_s(
        ld,
        ldap_base,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"mail", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    printf("search status: %d: %s\n", status, ldap_err2string(status));

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    printf("Getting email address to verify\n");
    char *ldap_email = *ldap_get_values(ld, *res, "mail");
    if (ldap_email == NULL)
    {
        printf("Email not found\n");
        print_and_quit(1);
    }

    // Use strstr to check if email is a substring of ldap_email
    if (strstr(email, ldap_email) == NULL)
    {
        printf("Email does not match\n");
        print_and_quit(1);
    }
    printf("Email successfully verified.\n");

    status = ldap_unbind_s(ld);
    // printf("unbind status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }
    printf("Successfully unbound from LDAP\n");
    printf("\n\n *** Successfully tested email-user *** \n\n");

    //////////////////////////////////////////////////////////////
    ////// debug for set-password

    printf("Connecting to LDAP as %s\n", bind_dn);
    // Initialize the LDAP connection
    ldap_initialize(&ld, ldap_uri);

    // Bind to the server
    status = ldap_bind_s(
        ld,
        bind_dn,
        bind_pw,
        LDAP_AUTH_SIMPLE);

    if (status != LDAP_SUCCESS)
    {
        printf("Failed to bind to LDAP\n");
        print_and_quit(status);
    }

    printf("Bind successful\n");

    sprintf(ldap_search_str, "(SamAccountName=%s)", username);

    status = ldap_search_ext_s(
        ld,
        ldap_base,
        LDAP_SCOPE_SUBTREE,
        ldap_search_str,
        (char *[]){"distinguishedName", NULL},
        0,
        NULL,
        NULL,
        &timeout,
        1,
        res);

    printf("search status: %d: %s\n", status, ldap_err2string(status));

    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    printf("Getting distinguished name\n");
    char *user_dn = *ldap_get_values(ld, *res, "distinguishedName");
    if (user_dn == NULL)
    {
        printf("User not found\n");
        print_and_quit(1);
    }
    printf("user_dn: %s\n", user_dn);

    // This is AD:

    // The AD unicodePwd attribute is very fiddly. We'll need to do the following:
    // 1. Enclose the password in quotes
    // 2. Convert the password to UTF-16LE (No BOM)
    // 3. Send the password as a binary value in an LDAP modify operation

    // So, first, add the quotes.
    char *newpasswd_quoted = malloc(strlen(newpasswd) + 3); // 2 characters for the quotes, 1 for the null terminator
    newpasswd_quoted[0] = '"';
    strcpy(newpasswd_quoted + 1, newpasswd);
    newpasswd_quoted[strlen(newpasswd) + 1] = '"';
    newpasswd_quoted[strlen(newpasswd) + 2] = 0;

    // Then, convert the quoted password to UTF-16LE (No BOM)
    uint8_t *newpasswd_utf16le = malloc(strlen(newpasswd_quoted) * 2); // 2 bytes per character, no null terminator or BOM

    for (int i = 0; i < (int)strlen(newpasswd_quoted); i++)
    {
        newpasswd_utf16le[i * 2] = newpasswd_quoted[i];
        newpasswd_utf16le[i * 2 + 1] = 0;
    }

    struct berval passwd_berval = {
        .bv_len = strlen(newpasswd_quoted) * 2,
        .bv_val = (char *)newpasswd_utf16le,
    };

    // Change the password
    LDAPMod mod = {
        .mod_op = LDAP_MOD_REPLACE | LDAP_MOD_BVALUES, // Binary replacement operation
        .mod_type = "unicodePwd",
        .mod_vals.modv_bvals = (struct berval *[]){&passwd_berval, NULL},
    };

    LDAPMod *mods[] = {&mod, NULL};

    status = ldap_modify_ext_s(
        ld,
        user_dn,
        mods,
        NULL,
        NULL);

    printf("modify status: %d: %s\n", status, ldap_err2string(status));
    if (status != LDAP_SUCCESS)
    {
        print_and_quit(status);
    }

    printf("Password successfully changed.\n");
}

int main(int argc, char **argv)
{

    printf("Content-Type: text/plain;charset=us-ascii\n\n");

    // This program operates based on a bunch of copies of the actual binary.
    // If the binary is called as "email-user", it will email the user a password reset link by
    //  calling the function email_user().
    // If the binary is called as `set-password`, it will generate a new password for the user,
    //  set it via LDAP, and display the new password to the user.
    // If the binary is called as anything else, it will print an error message and exit???

    if (argc != 1)
    {
        printf("Invalid number of arguments\n");
        exit(1);
    }

    // TODO: Is there a race condition here? Same seed for all runs that happen within a second of each other.
    srand(time(NULL));

    // Check to see if the binary was called as a command that ends with "email-user" or "set-password"
    if (strstr(argv[0], "email-user") != NULL)
    {
        email_user();
    }
    else if (strstr(argv[0], "set-password") != NULL)
    {
        set_password();
    }
    else if (strstr(argv[0], "crappasswd") != NULL)
    {
        debug();
    }
    else
    {
        printf("Invalid command\n");
        exit(1);
    }
}
