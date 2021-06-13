# soal-shift-sisop-modul-4-IT11-2021

## Disusun oleh :
1. Clarissa Fatimah (05311940000012)
2. Revina Rahmanisa (05311940000046)
3. Ghimnastiar AL Abiyyuna (05311940000042)

# Daftar Isi
## Daftar Isi 
* [SinSeiFS_IT11](#SinSeiFS_IT11) 
  * [Penyelesaian-1.](#penyelesaian-1) 
  * [Penyelesaian-2.](#penyelesaian-soal-2)
  * [Penyelesaian-3.](#penyelesaian-soal-3)
  * [Penyelesaian-4.](#penyelesaian-soal-4)
  * [Output.](#output-soal-1-dan-4) 
  * [Kendala.](#Kendala-Soal-1-dan-4) 

        
# SinSeiFS_IT11

## Penyelesaian-soal-1-dan-4
Di sini kami membuat fungsi atbash untuk mengenkripsi direktori yang memiliki awalan AtoZ_. Metode atbash sendiri merupakan suatu teknik enkripsi, dimana huruf alphabet disubtitusi dengan kebalikan dari abjadnya. Sehingga jika terdapat direktori yang nantinya dibuat dengan nama AtoZ_ atau direname menjadi AtoZ_ maka isi dari direktori itu akan terenkripsi.

Kemudian kami buat fungsi cek enkripsi untuk mengecek apakah direktori yang diinputkan terdapat nama AtoZ_ atau RX_. Jika terdapat nama AtoZ_ maka fungsi enkripsi atbash akan diterapkan pada direktori tersebut. Dan jika terdapat nama RX_ maka fungsi enkripsi rot13 dan atbash akan diterapkan pada direktori tersebut.

Kami membuat fungsi getatt untuk mendapatkan atribut dari file yang diminta dan menambahkan fungsi cek enkripsi juga.

Setelah itu kami membuat fungsi readdir untuk membaca direktori yang diminta. Fungsi ini juga menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi.

kemudian kami membuat fungsi read untuk mendapat data dari file yang dibuka. Fungsi ini juga menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi.

Kami membuat fungsi rename untuk merename folder sebelumnya menjadi nama folder yang diinginkan. Fungsi ini juga menambahkan fungsi cek enkripsi yang didefinisikan sebelumnya untuk mengecek nama direktori yang akan dienkripsi. Selain itu, fungsi ini akan menambahkan fungsi createlogrename untuk dicatat dalam log. Fungsi ini akan dijelaskan lebih lanjut di no.4.

#Nomor 4
Kami membuat fungsi createlog untuk mencatat proses yang telah dilakukan user sebelumnya seperti membuat atau menghapus direktori. Di sini kami membedakan levelnya. Terdapat level info dan warning. Level info dipakai untuk mencatat syscall rmdir dan unlink. Sedangkan level info untuk syscall yang lainnya.

fungsi createlog dan createlogrename ini ditambahkan ke setiap fungsi syscall yang dibuat. Agar semua syscall yang dilakukan oleh user dicatat dalam log yang sudah ditentukan sebelumnya.

``#include <errno.h>
#include <sys/time.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <pwd.h>
#include <grp.h>
#include <sys/xattr.h>
#include <sys/wait.h>
#include <pthread.h>

static const char *dirpath = "/home/nisa/Downloads";


void createlog(const char process[100], const char fpath[1000]) {
    char teks[2000];
    FILE *fp = fopen("/home/nisa/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    
    if (strcmp(process, "unlink") == 0) {
        sprintf(teks, "WARNING::%02d%02d%04d-%02d:%02d:%02d::UNLINK::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "mkdir") == 0) {
        sprintf(teks, "INFO::%02d%02d%04d-%02d:%02d:%02d::MKDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    else if (strcmp(process, "rmdir") == 0) {
        sprintf(teks, "WARNING::%02d%02d%04d-%02d:%02d:%02d::RMDIR::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, fpath);
    }
    for (int i = 0; teks[i] != '\0'; i++) {
            fputc(teks[i], fp);
    }
    fclose (fp);
}

void createlogrename(const char from[1000], const char to[1000]) {
    FILE *fp = fopen("/home/nisa/SinSeiFS.log", "a");
    time_t t = time(NULL);
    struct tm tm = *localtime(&t);
    char teks[2000];

    sprintf(teks, "INFO::%02d%02d%04d-%02d:%02d:%02d::RENAME::%s::%s\n", tm.tm_mday, tm.tm_mon + 1, tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec, from, to);
    for (int i = 0; teks[i] != '\0'; i++) {
            fputc(teks[i], fp);
    }
    fclose(fp);
}

void atbash(char *name) {
    if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) return;

    char *dot = strrchr(name, '.');
    char *atoz = strstr(name, "AtoZ_");
    int i;
    for (i = atoz - name; i < strlen(name); ++i) {
        if (name[i] == '/') {
            break;
        }
    }

    if (atoz == NULL) {
        i = 0;
    }

    int last = dot ? dot - name: strlen(name);
    for (; i < last; ++i) {
        if ('A' <= name[i] && name[i] <= 'Z') {
            name[i] = 155 - name[i];
        } else if ('a' <= name[i] && name[i] <= 'z') {
            name[i] = 219 - name[i];
        }
    }
}

void check_encryption(char *path, const char *fpath) {
    printf("check %s %s\n", path, fpath);
    if (strstr(fpath, "/AtoZ_") != NULL) {
        atbash(path);
    }
    printf("enc %s\n", path);
}

static int xmp_getattr(const char *path, struct stat *st) {
    char fpath[2000], name[1000], temp[1000];
    sprintf(temp, "%s", path);

    int name_len = strlen(path);
    for (int i = 0; i < name_len; i++) {
        name[i] = path[i + 1];
    }
    printf("getattr %s\n", name);
    check_encryption(temp, path);
    sprintf(fpath, "%s/%s", dirpath, temp);
    
    int res = lstat(fpath, st);
    if (res != 0){
        return -ENOENT;
    }

    return 0;
}

static int xmp_readdir(const char *path, void *buf, fuse_fill_dir_t filler, off_t offset, struct fuse_file_info *fi) {
    int res;
    DIR *dp;
    struct dirent *de;

    (void) offset;
    (void) fi;
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } 
    else {
        sprintf(name, "%s", path);
        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("readdir: %s\n", fpath);

    dp = opendir(fpath);
    if (dp == NULL)
        return -errno;

    while ((de = readdir(dp)) != NULL) {
        struct stat st;
        memset(&st, 0, sizeof(st));
        st.st_ino = de->d_ino;
        st.st_mode = de->d_type << 12;

        char fullpathname[2257];
        sprintf(fullpathname, "%s/%s", fpath, de->d_name);
        
        char temp[1000];
        strcpy(temp, de->d_name);
        check_encryption(temp, fpath);

        res = (filler(buf, temp, &st, 0));
        if (res != 0) break;
    }

    closedir(dp);

    return 0;
}

static int xmp_read(const char *path, char *buf, size_t size, off_t offset, struct fuse_file_info *fi) {
    char fpath[2000];
    char name[1000];

    if (strcmp(path, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", path);
        check_encryption(name, path);
        sprintf(fpath, "%s/%s", dirpath, name);
    }

    printf("read %s\n", fpath);
    
    int res = 0;
    int fd = 0 ;

    (void) fi;
    fd = open(fpath, O_RDONLY);
    if (fd == -1)
        return -errno;

    res = pread(fd, buf, size, offset);
    if (res == -1)
        res = -errno;

    close(fd);
    return res;
}

static int xmp_rename(const char *old, const char *new) {
    char fpath[2000];
    char name[1000];
    char new_name[1000];
    createlogrename(old, new);
    if (strcmp(old, "/") == 0) {
        sprintf(fpath, "%s", dirpath);
    } else {
        sprintf(name, "%s", old);
        check_encryption(name, fpath);

        memset(fpath, 0, sizeof(fpath));
        memset(new_name, 0, sizeof(new_name));

        sprintf(fpath, "%s/%s", dirpath, name);
        sprintf(new_name, "%s/%s", dirpath, new);
    }

    printf("rename %s %s\n", fpath, new_name);

    int res = rename(fpath, new_name);
    if (res == -1) 
        return -errno;

    return 0;
}

static int xmp_mkdir(const char *path, mode_t mode) {
    printf("mkdir %s\n", path);
    createlog("mkdir",path); 

    char fpath[2000];
    
    sprintf(fpath, "%s/%s", dirpath, path);
    mkdir(fpath, mode);

    return 0;
}

static int xmp_rmdir(const char *path) {
    printf("rmdir %s\n", path);
    createlog("rmdir", path);
    char fpath[2000];

    sprintf(fpath, "%s/%s", dirpath, path);
    int res = rmdir(fpath);
    if (res != 0) return -errno;

    return 0;
}

static struct fuse_operations xmp_oper = {
    .getattr    = xmp_getattr,
    .readdir    = xmp_readdir,
    .read       = xmp_read,
    .rename     = xmp_rename,
    .mkdir      = xmp_mkdir,
    .rmdir      = xmp_rmdir,
};

int main(int argc, char *argv[]) {
    umask(0);
    return fuse_main(argc, argv, &xmp_oper, NULL);

}``
## Penyelesaian-soal-2
Tidak berhasil terselesaikan
## Penyelesaian-soal-3
Tidak berhasil terselesaikan

## Output-soal-1-dan-dan-4
- Output Enzode AtoZ, Rename Decode AtoZ, dan Log
<img src="https://cdn.discordapp.com/attachments/594197008936337458/853657663225462834/unknown.png">
<img src="https://cdn.discordapp.com/attachments/594197008936337458/853657775980937236/unknown.png">
<img src="https://cdn.discordapp.com/attachments/594197008936337458/853657879595712522/unknown.png">
## Kendala-soal-1-dan-4


