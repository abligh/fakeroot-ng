#ifndef FILE_LIE_H
#define FILE_LIE_H

#include <stdio.h>

// Define functions for mapping the real files on disk to what they should be as far as the fake environment is concerned

#include "arch/platform.h"

struct stat_override {
    dev_t dev;
    ptlib_inode_t inode;
    mode_t mode;
    uid_t uid;
    gid_t gid;
    dev_t dev_id;
    bool transient;

    stat_override() : transient(false)
    {
    }
};

struct override_key {
    dev_t dev;
    ptlib_inode_t inode;

    override_key() : dev(0), inode(0)
    {
    }
    override_key( dev_t _dev, ino_t _inode ) : dev(_dev), inode(_inode)
    {
    }

    bool operator==( const override_key &rhs ) const { return dev==rhs.dev && inode==rhs.inode; }
};

// Returns the information inside the database about a file with the given dev and inode
// returns "false" if no such file exists
bool get_map( dev_t dev, ptlib_inode_t inode, struct stat_override *stat );

void set_map( const struct stat_override *stat );

void remove_map( dev_t dev, ptlib_inode_t inode );

void load_map( FILE *file );
void save_map( FILE *file );

#endif // FILE_LIE_H
