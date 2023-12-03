#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE
#endif
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L
#endif

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <uthash.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "conf.h"
#include "config.h"
#include "fapolicyd-backend.h"
#include "file.h"
#include "llist.h"
#include "md5-backend.h"
#include "message.h"

#include "filter.h"

static const char kEbuildBackend[] = "ebuilddb";

static int ebuild_init_backend(void);
static int ebuild_load_list(const conf_t *);
static int ebuild_destroy_backend(void);

backend ebuild_backend = {
		kEbuildBackend,
		ebuild_init_backend,
		ebuild_load_list,
		ebuild_destroy_backend,
		/* list initialization */
		{0, 0, NULL},
};

/*
 * Collection of paths and MD5s for a package
 */
typedef struct contents {
	char *md5;
	char *path;
} ebuildfiles;

/*
 * A package
 */

struct epkg {
	char *cpv;
	char *slot;
	char *repo;
	int files;
	ebuildfiles *content;
};

typedef struct {
    void (*process_entry)(struct dirent *, ...);
    int num_args;
    void *args[];
} func_struct;

/*
 * Remove the trailing newline from a string
 */
char* remove_newline(char* string) {
    int len = strlen(string);
    if (len > 0 && string[len-1] == '\n') {
        string[len-1] = '\0';
    }
    return string;
}

/*
 * Recursively process a directory
 *
 * This function takes a directory pointer and a function pointer as input.
 * It processes the directory based on the provided function pointer.
 *
 * @param dir The directory pointer.
 * @param process_entry The function pointer to the function to process the directory.
 * @param ... The variable argument list containing the additional arguments.
 * @return void
 */
void process_directory(DIR *dir, void (*process_entry)(struct dirent *, va_list), ...) {
	va_list args;
	va_start(args, process_entry);
	struct dirent *dp;
	while ((dp = readdir(dir)) != NULL) {
		if (dp->d_type == DT_DIR && strcmp(dp->d_name, ".") != 0 && strcmp(dp->d_name, "..") != 0) {
			process_entry(dp, args);
		}
	}
	va_end(args);
}

/*
 * Read from a VDB package directory and process SLOT, repository, CONTENTS
 * CATEGORY and PF are already known, but could be read at this stage
 *
 * This function takes a dirent pointer, an integer pointer, a struct epkg double pointer,
 * a character pointer for the category name, and a character pointer for the package name.
 * It processes the package directory based on the provided arguments.
 *
 * @param pkgdirdp The dirent pointer for the package directory.
 * @param args The variable argument list containing the additional arguments.
 *             The arguments should be in the following order:
 *             - int* packages: The integer pointer to store the number of packages.
 *             - struct epkg** vdbpackages: The double pointer to struct epkg to store the packages.
 *             - char* categoryname: The character pointer for the category name.
 *             - char* pkgname: The character pointer for the package name.
 */
void process_pkgdir(struct dirent *pkgdirdp, va_list args) {
	msg(LOG_DEBUG,"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
	int *packages = va_arg(args, int*);
	struct epkg **vdbpackages = va_arg(args, struct epkg**);
	char *categoryname = va_arg(args, char*);
	char *pkgname = va_arg(args, char*);

	char *pkgrepo = NULL;
	char *pkgslot = NULL;
	int pkgfiles = 0;
	ebuildfiles* pkgcontents = NULL;

	char *fileNames[] = {"SLOT", "repository", "CONTENTS"};
	int fileCount = sizeof(fileNames) / sizeof(fileNames[0]);

	for (int i = 0; i < fileCount; i++) {
		#ifdef DEBUG
		msg(LOG_DEBUG, "\tProcessing %s", fileNames[i]);
		#endif
		if (pkgdirdp->d_type == DT_REG && strcmp(pkgdirdp->d_name, fileNames[i]) == 0) {
			char *filePath;
			if (asprintf(&filePath, "/var/db/pkg/%s/%s/%s", categoryname, pkgname, pkgdirdp->d_name) == -1) {
				perror("asprintf");
				filePath = NULL;
			}
			if (filePath) {
				FILE *fp;
				char *line = NULL;
				size_t len = 0;
				ssize_t read;
				if ((fp = fopen(filePath, "r")) == NULL) {
					msg(LOG_ERR, "Could not open %s", filePath);
					free(filePath);
					return;
				}

				if (strcmp(fileNames[i], "SLOT") == 0 || strcmp(fileNames[i], "repository") == 0) {
					// SLOT and repository will only ever contain a single line
					if ((read = getline(&line, &len, fp)) != -1) {
						if (strcmp(fileNames[i], "SLOT") == 0) {
							pkgslot = strdup(line);
							remove_newline(pkgslot);
							#ifdef DEBUG
							msg(LOG_DEBUG, "\tslot: %s", pkgslot);
							#endif
						} else if (strcmp(fileNames[i], "repository") == 0) {
							pkgrepo = strdup(line);
							remove_newline(pkgrepo);
							#ifdef DEBUG
							msg(LOG_DEBUG, "\trepo: %s", pkgrepo);
							#endif
						}
					}
				} else if (strcmp(fileNames[i], "CONTENTS") == 0) {
					while ((read = getline(&line, &len, fp)) != -1) {
						char *token;
						char *saveptr;

						token = strtok_r(line, " ", &saveptr); // obj/dir/sym, /path/to/file, md5, datestamp

						if (token) {
							// we only care about files
							if ((strcmp(token, "dir")) == 0 || (strcmp(token, "sym")) == 0) {
								continue;
							}

							ebuildfiles *file = malloc(sizeof(ebuildfiles));
							token = strtok_r(NULL, " ", &saveptr);
							file->path = strdup(token);
							token = strtok_r(NULL, " ", &saveptr);
							file->md5 = strdup(token);

							// we don't care about the datestamp

							pkgcontents = realloc(pkgcontents, sizeof(ebuildfiles) * (pkgfiles + 1));
							pkgcontents[pkgfiles] = *file;
							pkgfiles++;
							free(file);
						}
					}
				}

				free(line);
				free(filePath);
			}
		}
	}

	// Construct a CPVR string e.g. dev-libs/libxml2-2.9.10{-r0}
	// We're not processing based on this information, but it's useful for logging
	// If there's a need to split into components see
	// https://github.com/gentoo/portage-utils/blob/master/libq/atom.c
	char *catpkgver = malloc(strlen(categoryname) + strlen(pkgname) + 2);
	if (catpkgver == NULL) {
		msg(LOG_ERR, "Could not allocate memory.");
		return;
	}
	strcpy(catpkgver, categoryname);
	strcat(catpkgver, "/");
	strcat(catpkgver, pkgname);

	// make a new package
	struct epkg *package = malloc(sizeof(struct epkg));
	package->cpv = strdup(catpkgver);
	package->slot = strdup(pkgslot);
	package->repo = strdup(pkgrepo);
	package->files = pkgfiles;
	package->content = pkgcontents;

	// add it to the array
	*vdbpackages = realloc(*vdbpackages, sizeof(struct epkg) * (*packages + 1));
	*vdbpackages[*packages] = *package;
	(*packages)++;

	#ifdef DEBUG
	msg(LOG_DEBUG, "Package %s\n\tSlot %s\n\tRepo %s\n\tFiles %i",
		package->cpv, package->slot, package->repo, package->files);
	#endif
	free(catpkgver);
	free(pkgslot);
	free(pkgrepo);
	free(package);
}


/**
 * For a directory pointer within a category, process a package
 *
 * It takes in a dirent structure pointer and a variable argument list
 * The packages and vdbpackages pointers are extracted from the variable argument list.
 *
 * @param pkgdp A pointer to a dirent structure representing a package.
 * @param args A variable argument list containing the packages, vdbpackages, and category name.
 *             The arguments should be passed in the following order:
 *             - packages: A pointer to the packages.
 *             - vdbpackages: A pointer to the vdbpackages.
 *             - category_name: The name of the category.
 * @return void
 */
void process_vdb_package(struct dirent *pkgdp, va_list args) {
	int *packages = va_arg(args, int*);
	struct epkg **vdbpackages = va_arg(args, struct epkg**);
	char *categoryname = va_arg(args, char*);
	char *pkgpath;
	// construct the package directory path using the category name and package name
	if (asprintf(&pkgpath, "/var/db/pkg/%s/%s", categoryname, pkgdp->d_name) == -1) {
		pkgpath = NULL;
		perror("asprintf");
	}

	msg(LOG_INFO, "Loading package %s/%s", categoryname, pkgdp->d_name);

	if (pkgpath) {
		DIR *pkgdir;
		if ((pkgdir = opendir(pkgpath)) == NULL) {
			msg(LOG_ERR, "Could not open %s", pkgpath);
			msg(LOG_ERR, "Error: %s", strerror(errno));
			free(pkgpath);
			return;
		}

		process_directory(pkgdir, process_pkgdir, packages, vdbpackages, categoryname, pkgdp->d_name);
		closedir(pkgdir);
		free(pkgpath);
	}
}

/*
 * For a directory pointer within the VDB root, process a directory (category)
 *
 * This function opens a category directory and processes its contents.
 * It takes a `struct dirent` pointer and a variable argument list as input.
 *
 * @param vdbdp A pointer to a `struct dirent` representing the category directory entry.
 * @param args   A variable argument list containing the following arguments:
 *               - packages: A pointer to an integer representing the number of packages.
 *               - vdbpackages: A pointer to an array of `struct epkg` pointers representing the vdb packages.
 */
void process_vdb_category(struct dirent *vdbdp, va_list args) {
	int *packages = va_arg(args, int*);
	struct epkg **vdbpackages = va_arg(args, struct epkg**);
	char *catdir;
	// construct the category directory path
	if (asprintf(&catdir, "/var/db/pkg/%s", vdbdp->d_name) == -1) {
		catdir = NULL;
		perror("asprintf");
	}

	msg(LOG_INFO, "Loading category %s", vdbdp->d_name);

	if (catdir) {
		DIR *category;
		if ((category = opendir(catdir)) == NULL) {
			msg(LOG_ERR, "Could not open %s", catdir);
			msg(LOG_ERR, "Error: %s", strerror(errno));
			free(catdir);
			return;
		}

		process_directory(category, process_vdb_package, packages, vdbpackages, vdbdp->d_name);
		closedir(category);
		free(catdir);
	}
}

/*
 * Exclude a known list of paths that shouldn't contain binaries
 * (installed by a package manager, anyway).
 */
int exclude_path(const char *path) {
	const char *excluded_paths[] = {
	"/usr/share/",
	"/usr/src/",
	};
	const int num_excluded_paths = sizeof(excluded_paths) / sizeof(excluded_paths[0]);
	for (int i = 0; i < num_excluded_paths; i++) {
		if (strncmp(path, excluded_paths[i], strlen(excluded_paths[i])) == 0) {
			return 1;
		}
	}
	return 0;
}

/*
 * Portage stores data about installed packages in the VDB (/var/db/pkg/).
 * We care about /var/db/pkg/category/package-version/CONTENTS
 * which lists files and directories that are installed as part of a package 'merge'
 * operation. All files are prefixed with 'obj' and are in the format:
 * obj /path/to/file $(md5sum /path/to/file) $(date -r /path/to/file "+%s")
 * e.g.
 * obj /usr/bin/clamscan 3ade185bd024e29880e959e6ad187515 1693552964
 */
static int ebuild_load_list(const conf_t *conf) {
	list_empty(&ebuild_backend.list);
	struct _hash_record *hashtable = NULL;
	struct _hash_record **hashtable_ptr = &hashtable;

	DIR *vdbdir;

	if ((vdbdir = opendir("/var/db/pkg")) == NULL) {
		msg(LOG_ERR, "Could not open /var/db/pkg");
		return 1;
	}

	struct epkg *vdbpackages = NULL;
	int packages = 0;

	msg(LOG_INFO, "Initialising ebuild backend");
	msg(LOG_DEBUG, "Processing VDB");
	/*
	 * recurse through category/package-version/ dirs,
	 * process CONTENTS (files, md5s), repository, SLOT,
	 * store in epkg array
	*/
	process_directory(vdbdir, process_vdb_category, &packages, &vdbpackages);
	closedir(vdbdir);

	msg(LOG_INFO, "Processed %d packages.", packages);

	for (int j = 0; j < packages; j++) {
		struct epkg *package = &vdbpackages[j];

		// slot "0" is the default slot for packages that aren't slotted; we don't need to include it in the log
		// TODO: Files listed here include paths we filter in add_file_to_backend_by_md5
		if ((strcmp(package->slot,"0")) == 0) {
			msg(LOG_INFO, "Adding %s:%s (::%s) to the ebuild backend; %i files",
				package->cpv, package->slot, package->repo, package->files);
		} else {
			msg(LOG_INFO, "Adding %s (::%s) to the ebuild backend; %i files",
				package->cpv, package->repo, package->files);
		}
		for (int k = 0; k < package->files; k++) {
			ebuildfiles *file = &package->content[k];
			// skip files in excluded paths
			if (exclude_path(file->path)) {
				continue;
			}
			add_file_to_backend_by_md5(file->path, file->md5, hashtable_ptr, SRC_EBUILD, &ebuild_backend);
		}
	}
	free(vdbpackages);
	return 0;
}

static int ebuild_init_backend(void)
{
	if (filter_init())
		return 1;

	if (filter_load_file()) {
		filter_destroy();
		return 1;
	}

	list_init(&ebuild_backend.list);

	return 0;
}

static int ebuild_destroy_backend(void)
{
	filter_destroy();
	list_empty(&ebuild_backend.list);
	return 0;
}
