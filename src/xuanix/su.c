#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pwd.h>
#include <grp.h>
#include <shadow.h>
#include <crypt.h>
#include <errno.h>

static const char *prog;

static void die(const char *msg) {
    fprintf(stderr, "%s: %s\n", prog, msg);
    exit(1);
}

static int verify_password(const char *user) {
    struct spwd *sp = getspnam(user);
    if (!sp || !sp->sp_pwdp || !*sp->sp_pwdp) {
        fprintf(stderr, "%s: authentication failed\n", prog);
        return 0;
    }
    if (sp->sp_pwdp[0] == '!' || sp->sp_pwdp[0] == '*') {
        fprintf(stderr, "%s: account locked\n", prog);
        return 0;
    }
    char *input = getpass("Password: ");
    if (!input) return 0;
    char *hashed = crypt(input, sp->sp_pwdp);
    return hashed && strcmp(hashed, sp->sp_pwdp) == 0;
}

int main(int argc, char **argv) {
    prog = "su";
    int opt;
    int login_shell = 0;
    int preserve_env = 0;
    char *command = NULL;
    char *shell_opt = NULL;
    char *target = "root";

    while ((opt = getopt(argc, argv, "c:flmps:g:G:")) != -1) {
        switch (opt) {
        case 'c': command = optarg; break;
        case 'f': break;
        case 'l': login_shell = 1; break;
        case 'm':
        case 'p': preserve_env = 1; break;
        case 's': shell_opt = optarg; break;
        case 'g':
        case 'G': break;
        default:
            fprintf(stderr, "Usage: %s [-l] [-c cmd] [-s shell] [user]\n", prog);
            return 1;
        }
    }

    if (optind < argc && strcmp(argv[optind], "-") == 0) {
        login_shell = 1;
        optind++;
    }
    if (optind < argc) target = argv[optind++];

    struct passwd *pw = getpwnam(target);
    if (!pw) {
        fprintf(stderr, "%s: user %s does not exist\n", prog, target);
        return 1;
    }

    uid_t ruid = getuid();

    if (ruid != 0) {
        if (!verify_password(target)) {
            fprintf(stderr, "%s: incorrect password\n", prog);
            return 1;
        }
    }

    if (initgroups(pw->pw_name, pw->pw_gid) != 0) {
        perror("initgroups");
        return 1;
    }
    if (setgid(pw->pw_gid) != 0) { perror("setgid"); return 1; }
    if (setuid(pw->pw_uid) != 0) { perror("setuid"); return 1; }

    if (login_shell && !preserve_env) {
        clearenv();
        setenv("HOME", pw->pw_dir, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        setenv("SHELL", pw->pw_shell[0] ? pw->pw_shell : "/bin/sh", 1);
        setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);
        setenv("TERM", getenv("TERM") ? getenv("TERM") : "linux", 1);
    } else if (!preserve_env) {
        setenv("HOME", pw->pw_dir, 1);
        setenv("USER", pw->pw_name, 1);
        setenv("LOGNAME", pw->pw_name, 1);
        if (pw->pw_uid != 0) {
            setenv("SHELL", pw->pw_shell[0] ? pw->pw_shell : "/bin/sh", 1);
        }
    }

    if (login_shell) {
        if (chdir(pw->pw_dir) != 0) chdir("/");
    }

    const char *shell = shell_opt
        ? shell_opt
        : (pw->pw_shell[0] ? pw->pw_shell : "/bin/sh");

    if (command) {
        char *args[] = { (char *)shell, "-c", command, NULL };
        execv(shell, args);
        perror("execv");
        return 1;
    } else if (login_shell) {
        char *base = strrchr(shell, '/');
        base = base ? base + 1 : (char *)shell;
        char arg0[256];
        snprintf(arg0, sizeof(arg0), "-%s", base);
        char *args[] = { arg0, NULL };
        execv(shell, args);
        perror("execv");
        return 1;
    } else {
        char *args[] = { (char *)shell, NULL };
        execv(shell, args);
        perror("execv");
        return 1;
    }
}
