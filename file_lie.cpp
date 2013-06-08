/*
    Fakeroot Next Generation - run command with fake root privileges
    This program is copyrighted. Copyright information is available at the
    AUTHORS file at the root of the source tree for the fakeroot-ng project

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
*/
#include "config.h"

#include <unordered_map>

#include <sys/types.h>
#include <unistd.h>

#include "file_lie.h"

struct db_key_hash {
    size_t operator()(const override_key &key) const { return key.inode; };
};

typedef std::unordered_map<override_key, stat_override, db_key_hash> file_hash;

static file_hash map_hash;

bool get_map( dev_t dev, ptlib_inode_t inode, stat_override *stat )
{
    file_hash::iterator i(map_hash.find( override_key( dev, inode) ));

    if( i!=map_hash.end() ) {
        *stat=i->second;
        return true;
    } else {
        return false;
    }
}

void set_map( const stat_override *stat )
{
    map_hash[override_key(stat->dev, stat->inode)]=*stat;
}

void remove_map( dev_t dev, ptlib_inode_t inode )
{
    file_hash::iterator i(map_hash.find( override_key( dev, inode) ));

    if( i!=map_hash.end() )
        map_hash.erase(i);
}

void load_map( FILE *file )
{
    stat_override override;
    int params;

    while( (params=fscanf(file, "dev=" DEV_F ", ino=" INODE_F ", mode=%o, uid=%d, gid=%d, rdev=" DEV_F " \n", &override.dev, &override.inode,
            &override.mode, &override.uid, &override.gid, &override.dev_id ))==6 )
    {
        set_map( &override );
    }
}

void save_map( FILE *file )
{
    for( file_hash::const_iterator i=map_hash.begin(); i!=map_hash.end() ; ++i ) {
        const struct stat_override *override;

        override=&(i->second);
        if( !override->transient ) {
            fprintf( file, "dev=" DEV_F ",ino=" INODE_F ",mode=%o,uid=%d,gid=%d,rdev=" DEV_F "\n", override->dev, override->inode,
                    override->mode, override->uid, override->gid, override->dev_id );
        }
    }
}
